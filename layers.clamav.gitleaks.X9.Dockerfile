# syntax=docker/dockerfile:1
#
# Layer-aware X9: scans EVERY layer of the target image on its own, plus the
# image config (ENV / LABEL / build history), instead of only the merged rootfs.
#
# Why the `distroless.*` files are not enough
# -------------------------------------------
# `COPY --from=target / /scanroot` hands the scanners the *flattened* view.
# Anything that was added in one layer and removed (whiteout) or overwritten
# in a later one is invisible there, yet it still ships inside the image and
# is recoverable by anyone who can pull it:
#
#     RUN curl -H "Authorization: $TOKEN" ... && ...    # TOKEN lands in history
#     COPY id_rsa /root/.ssh/                           # layer 5 keeps the key
#     RUN rm /root/.ssh/id_rsa                          # layer 6 only "hides" it
#
# This file therefore needs the image as a tarball (layers + config), not as
# a filesystem. Produce one with any of:
#
#     docker save    your_image_to_be_scanned -o target-archive/target.tar
#     skopeo copy    docker://registry/img:tag  docker-archive:target-archive/target.tar
#     crane pull     registry/img:tag           target-archive/target.tar
#
# Usage
# -----
#   mkdir -p target-archive && docker save your_image_to_be_scanned -o target-archive/target.tar
#   docker buildx build -f layers.clamav.gitleaks.X9.Dockerfile \
#     --build-context target-archive=./target-archive \
#     --build-arg CACHEBUST="$(date +%s)" \
#     --output type=local,dest=./reports  \
#     .
#
# Reports
#   layers_inventory.json         every layer: diff_id, created_by, file count, whiteouts
#   layers_ghost_files.json       files that exist in a layer but NOT in the final image
#   clamav_layers_report.json     malware found in any layer (path tells the layer: /layers/NNN_<diffid>/...)
#   gitleaks_layers_report.json   secrets in any layer + in env/labels/history
#
# Hardening of the pipeline itself
#   * the target is never executed: it is only data unpacked by GNU tar
#   * scanners run as an unprivileged user and with `RUN --network=none`, so an
#     exploited parser (ClamAV have had such CVEs) can neither exfiltrate
#     nor reach the network; signature DBs are fetched in a separate step
#   * pin the scanner images by digest (tool@sha256:...) in real use: they are a
#     supply-chain target and `latest` silently changes under you
#   * CACHEBUST forces fresh signature/vuln DBs; without it BuildKit happily
#     reuses yesterday's cached "clean" result

ARG REGISTRY=docker.io
ARG CLAMAV_IMAGE=clamav/clamav:stable
ARG GITLEAKS_IMAGE=zricethezav/gitleaks:latest
ARG BASE_IMAGE=alpine:latest

FROM ${REGISTRY}/${CLAMAV_IMAGE} AS clamav
FROM ${REGISTRY}/${GITLEAKS_IMAGE} AS gitleaks

FROM ${REGISTRY}/${BASE_IMAGE} AS base
SHELL ["/bin/sh", "-eu", "-o", "pipefail", "-c"]
RUN apk add --no-cache tar jq gzip zstd \
  && adduser -D -H -u 10001 scanner \
  && mkdir -p /reports && chown scanner /reports

FROM base AS layers-stage
COPY --from=target-archive target.tar /input/target.tar
COPY --chmod=0755 extract_layers.sh /usr/local/bin/extract_layers.sh
RUN --network=none \
  extract_layers.sh /input/target.tar /layers /reports \
  && chmod -R a+rX /layers \
  && chown -R scanner /reports

FROM layers-stage AS clamscan-stage
ARG CACHEBUST
RUN apk add --no-cache clamav clamav-libunrar
COPY --from=clamav --chown=clamav /var/lib/clamav/ /var/lib/clamav/
RUN echo "db refresh ${CACHEBUST:-}" \
  && (freshclam --stdout || echo "WARNING: freshclam failed, using DB baked in ${CLAMAV_IMAGE:-clamav image}" >&2)
COPY --chmod=0755 clamav_report_to_json.sh /usr/local/bin/clamav_report_to_json.sh
USER scanner
WORKDIR /reports
RUN --network=none \
  rc=0; \
  clamscan -r -i \
  --max-filesize=2000M --max-scansize=4000M \
  --max-files=100000 --max-recursion=64 \
  --alert-exceeds-max=yes --alert-encrypted=yes --alert-broken=yes \
  --scan-archive=yes --follow-dir-symlinks=0 --follow-file-symlinks=0 \
  /layers > clamav_layers_report.txt 2> clamav_layers_errors.txt || rc=$?; \
  [ "$rc" -le 1 ] || { echo "clamscan failed (exit $rc)" >&2; cat clamav_layers_errors.txt >&2; exit "$rc"; }; \
  clamav_report_to_json.sh clamav_layers_report.txt > clamav_layers_report.json

FROM layers-stage AS gitleaks-stage
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
USER scanner
WORKDIR /reports
RUN --network=none \
  gitleaks dir /layers \
  --no-banner --redact=80 \
  --max-target-megabytes=50 \
  --report-format=json \
  --report-path=gitleaks_layers_report.json \
  --exit-code=0

FROM scratch AS final-stage
COPY --from=layers-stage   /reports/layers_inventory.json /reports/layers_ghost_files.json /
COPY --from=clamscan-stage /reports/clamav_layers_report.json /reports/clamav_layers_report.txt /
COPY --from=gitleaks-stage /reports/gitleaks_layers_report.json /
