#!/bin/sh

# Usage:
#   ./clamav_report_to_json.sh report.txt
#   clamscan -r /scan/path | ./clamav_report_to_json.sh

INPUT="${1:-/dev/stdin}"

awk '
BEGIN {
    print "{"
    first = 1
}

/^-+ SCAN SUMMARY -+/ {
    in_summary = 1
    next
}

in_summary && NF {
    line = $0

    # split on first colon
    split(line, parts, ":")
    key = parts[1]

    value = substr(line, index(line, ":") + 1)

    # trim spaces
    gsub(/^[ \t]+/, "", value)
    gsub(/[ \t]+$/, "", value)

    # normalize key
    gsub(/ /, "_", key)
    gsub(/\(/, "", key)
    gsub(/\)/, "", key)

    # lowercase key
    key = tolower(key)

    if (!first) {
        printf(",\n")
    }
    first = 0

    printf("  \"%s\": \"%s\"", key, value)
}

END {
    print "\n}"
}
' "$INPUT"
