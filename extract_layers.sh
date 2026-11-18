#!/bin/sh
#
# Explode a saved container image into one directory per layer, so scanners
# can see content that the final (flattened) filesystem hides.
#
# Usage:
#   ./extract_layers.sh <image-archive.tar> <output-dir> <reports-dir>
#
# Accepts `docker save` archives (legacy and OCI-layout flavours), skopeo
# `docker-archive:` and `oci-archive:` tarballs. Layers may be plain, gzip or
# zstd compressed (GNU tar auto-detects; zstd binary needed for zstd).
#
# Produces:
#   <output-dir>/NNN_<digest12>/        rootfs fragment of layer NNN (1-based)
#   <output-dir>/_image_config/         config.json, history.txt, env.txt, labels.txt
#   <reports>/layers_inventory.json     per-layer digest, created_by, counts, whiteouts
#   <reports>/layers_ghost_files.json   files present in some layer but NOT in the
#                                       final image (deleted or overwritten later)

set -eu

ARCHIVE="${1:?usage: $0 <image-archive.tar> <output-dir> <reports-dir>}"
OUT="${2:?missing output dir}"
REPORTS="${3:?missing reports dir}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$OUT" "$REPORTS"

tar --version 2>/dev/null | grep -q 'GNU tar' || { echo "extract_layers: GNU tar required (apk add tar)" >&2; exit 2; }
command -v jq >/dev/null || { echo "extract_layers: jq required" >&2; exit 2; }

# The archive itself is attacker-controlled: GNU tar already refuses absolute
# paths and `..` members; also never restore ownership/permissions/devices.
TAR_SAFE="--no-same-owner --no-same-permissions --delay-directory-restore --warning=no-unknown-keyword"

tar -xf "$ARCHIVE" -C "$WORK" $TAR_SAFE

blob_path() { # sha256:abc... -> path inside an OCI layout
  echo "$WORK/blobs/${1%%:*}/${1#*:}"
}

if [ -f "$WORK/manifest.json" ]; then
  # docker save / docker-archive (also present in Docker >= 25 OCI-flavoured saves)
  CONFIG="$WORK/$(jq -r '.[0].Config' "$WORK/manifest.json")"
  jq -r '.[0].Layers[]' "$WORK/manifest.json" | sed "s|^|$WORK/|" > "$WORK/.layers"
elif [ -f "$WORK/index.json" ]; then
  # Plain OCI layout. Resolve nested indexes, preferring linux/amd64.
  ref="$(jq -r '.manifests[0].digest' "$WORK/index.json")"
  while :; do
    m="$(blob_path "$ref")"
    if jq -e '.manifests' "$m" >/dev/null 2>&1; then
      ref="$(jq -r '( [.manifests[] | select(.platform.os=="linux" and .platform.architecture=="amd64")] + .manifests )[0].digest' "$m")"
      continue
    fi
    break
  done
  CONFIG="$(blob_path "$(jq -r '.config.digest' "$m")")"
  jq -r '.layers[].digest' "$m" | while read -r d; do blob_path "$d"; done > "$WORK/.layers"
else
  echo "extract_layers: unknown archive format (no manifest.json / index.json)" >&2
  exit 2
fi

# ---------------------------------------------------------------- image config
# The config is a frequent leak on its own: ENV values, LABELs and the build
# history (`created_by`) keep ARG values and full RUN command lines.
CFG_DIR="$OUT/_image_config"
mkdir -p "$CFG_DIR"
cp "$CONFIG" "$CFG_DIR/config.json"
jq -r '.history[]? | .created_by // ""' "$CONFIG" > "$CFG_DIR/history.txt"
jq -r '.config.Env[]?' "$CONFIG" > "$CFG_DIR/env.txt"
jq -r '.config.Labels // {} | to_entries[] | "\(.key)=\(.value)"' "$CONFIG" > "$CFG_DIR/labels.txt"
# created_by for history entries that really produced a layer, in layer order
jq -r '.history[]? | select(.empty_layer != true) | (.created_by // "") | gsub("[\t\n]"; " ")' \
  "$CONFIG" > "$WORK/.created_by"

# --------------------------------------------------------------- layer explode
: > "$WORK/.listing"   # "<layer>\t<path>" for every entry of every layer
: > "$WORK/.inventory" # one JSON object per line
i=0
while read -r blob; do
  i=$((i + 1))
  # DiffID (uncompressed digest) from the config is what `docker history`,
  # trivy and the registry UI show; fall back to the blob file name.
  diffid="$(jq -r --argjson n "$((i - 1))" '.rootfs.diff_ids[$n] // empty' "$CONFIG")"
  [ -n "$diffid" ] || diffid="sha256:$(sha256sum "$blob" | cut -d' ' -f1)"
  hex="${diffid#*:}"
  dir="$OUT/$(printf '%03d' "$i")_$(printf '%.12s' "$hex")"
  mkdir -p "$dir"

  tar -tf "$blob" | sed -e 's|^\./||' -e '/^$/d' > "$WORK/.l$i"
  if ! tar -xf "$blob" -C "$dir" $TAR_SAFE --no-overwrite-dir 2>"$WORK/.err$i"; then
    echo "extract_layers: layer $i extracted with errors (kept partial):" >&2
    sed 's/^/  /' "$WORK/.err$i" >&2
  fi
  chmod -R u+rwX "$dir" 2>/dev/null || true

  awk -v L="$i" '{ print L "\t" $0 }' "$WORK/.l$i" >> "$WORK/.listing"

  created_by="$(sed -n "${i}p" "$WORK/.created_by")"
  files="$(grep -vc '/$' "$WORK/.l$i" || true)"
  grep -E '(^|/)\.wh\.' "$WORK/.l$i" > "$WORK/.wh$i" || true
  jq -cn --argjson layer "$i" --arg diff_id "$diffid" --arg dir "$dir" \
        --arg created_by "$created_by" --argjson files "$files" \
        --rawfile wh "$WORK/.wh$i" \
     '{layer:$layer, diff_id:$diff_id, dir:$dir, created_by:$created_by,
       files:$files, whiteouts:($wh | split("\n") | map(select(length>0)))}' \
     >> "$WORK/.inventory"
done < "$WORK/.layers"

jq -s '.' "$WORK/.inventory" > "$REPORTS/layers_inventory.json"

# ------------------------------------------------------------- ghost detection
# Replay the layers in order applying OCI whiteout semantics:
#   dir/.wh.<name>    -> <name> (and everything below it) removed
#   dir/.wh..wh..opq  -> everything previously under dir/ removed
#   same path again   -> previous content overwritten (still in the old layer)
awk -F '\t' '
  function base(p) { sub(/\/$/, "", p); n = split(p, a, "/"); return a[n] }
  function parent(p) { sub(/\/$/, "", p); if (p !~ /\//) return ""; sub(/\/[^\/]*$/, "", p); return p "/" }
  function bury(k, fate, at) {
    if (k in alive) {
      ghost[++g] = k "\t" alive[k] "\t" fate "\t" at
      delete alive[k]
    }
  }
  {
    L = $1; p = $2
    b = base(p)
    if (b == ".wh..wh..opq") {
      d = parent(p)
      for (k in alive) if (alive[k] < L && index(k, d) == 1) bury(k, "deleted (opaque dir)", L)
      next
    }
    if (b ~ /^\.wh\./) {
      t = parent(p) substr(b, 5)
      for (k in alive) if (alive[k] < L && (k == t || index(k, t "/") == 1)) bury(k, "deleted (whiteout)", L)
      next
    }
    if (p ~ /\/$/) next              # directories are not interesting by themselves
    if ((p in alive) && alive[p] < L) bury(p, "overwritten", L)
    alive[p] = L
  }
  END { for (n = 1; n <= g; n++) print ghost[n] }
' "$WORK/.listing" > "$WORK/.ghosts"

jq -R -s --arg out "$OUT" '
  split("\n") | map(select(length>0) | split("\t")
    | {path: .[0], added_in_layer: (.[1]|tonumber), fate: .[2], at_layer: (.[3]|tonumber)})
' "$WORK/.ghosts" > "$REPORTS/layers_ghost_files.json"

echo "extract_layers: $i layers -> $OUT ; $(jq length "$REPORTS/layers_ghost_files.json") ghost file(s)"
