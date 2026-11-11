#!/bin/sh

# Usage:
#   ./clamav_report_to_json.sh report.txt
#   clamscan -r -i /scan/path | ./clamav_report_to_json.sh
#
# Output:
#   { "infected": [ {"file": "...", "signature": "..."} ... ],
#     "summary":  { "known_viruses": "...", ... } }
#
# Paths come from the scanned (untrusted) image, so every string is JSON-escaped.

INPUT="${1:-/dev/stdin}"

awk '
function esc(s) {
    gsub(/\\/, "\\\\", s)
    gsub(/"/, "\\\"", s)
    gsub(/\t/, "\\t", s)
    gsub(/\r/, "\\r", s)
    gsub(/[\001-\037]/, "?", s)
    return s
}

BEGIN { n_inf = 0; n_sum = 0 }

/^-+ SCAN SUMMARY -+/ { in_summary = 1; next }

# "<path>: <Signature> FOUND"  (path may itself contain ": ")
!in_summary && / FOUND$/ {
    line = $0
    sub(/ FOUND$/, "", line)
    pos = 0
    for (i = length(line); i > 1; i--) if (substr(line, i - 1, 2) == ": ") { pos = i - 1; break }
    if (pos) {
        inf_file[++n_inf] = substr(line, 1, pos - 1)
        inf_sig[n_inf]    = substr(line, pos + 2)
    }
    next
}

in_summary && NF && index($0, ":") {
    key = substr($0, 1, index($0, ":") - 1)
    value = substr($0, index($0, ":") + 1)
    gsub(/^[ \t]+|[ \t]+$/, "", value)
    gsub(/ /, "_", key); gsub(/[()]/, "", key)
    sum_key[++n_sum] = tolower(key)
    sum_val[n_sum] = value
}

END {
    print "{"
    print "  \"infected\": ["
    for (i = 1; i <= n_inf; i++)
        printf("    {\"file\": \"%s\", \"signature\": \"%s\"}%s\n", esc(inf_file[i]), esc(inf_sig[i]), (i < n_inf ? "," : ""))
    print "  ],"
    print "  \"summary\": {"
    for (i = 1; i <= n_sum; i++)
        printf("    \"%s\": \"%s\"%s\n", esc(sum_key[i]), esc(sum_val[i]), (i < n_sum ? "," : ""))
    print "  }"
    print "}"
}
' "$INPUT"
