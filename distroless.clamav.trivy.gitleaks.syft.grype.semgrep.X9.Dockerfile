# NOTE: scans the *flattened* rootfs only.
#
# sudo docker buildx build -t suspectimage \
#   --build-arg REGISTRY=docker.io \
#   --build-arg CLAMAV_IMAGE=clamav/clamav:stable \
#   --build-arg TRIVY_IMAGE=aquasec/trivy:latest \
#   --build-arg GITLEAKS_IMAGE=zricethezav/gitleaks:latest \
#   --build-arg SYFT_IMAGE=anchore/syft:latest \
#   --build-arg GRYPE_IMAGE=anchore/grype:latest \
#   --build-arg SEMGREP_IMAGE=semgrep/semgrep:latest \
#   --build-arg BASE_IMAGE=alpine:latest \
#   --build-arg TARGET_IMAGE=your_image_to_be_scanned \
#   --build-arg CLAMAV_WORKDIR=. \
#   --build-arg TRIVY_WORKDIR=. \
#   --build-arg TRIVY_SEVERITY=CRITICAL,HIGH \
#   --build-arg GITLEAKES_WORKDIR=. \
#   --build-arg SYFT_WORKDIR=. \
#   --build-arg SEMGREP_WORKDIR=. \
#   --build-arg CACHEBUST="$(date +%s)" \
#   --output type=local,dest=./reports \
#   .
#
# --output exports the scratch final stage straight to ./reports
# OR
# sudo docker create --name suspectcontainer -it suspectimage /bin/sh
# sudo docker cp suspectcontainer:/reports ./reports
# sudo docker rm suspectcontainer
# THEN
# sudo docker system prune --all --volumes --force

ARG REGISTRY=docker.io
ARG CLAMAV_IMAGE=clamav/clamav:stable
ARG TRIVY_IMAGE=aquasec/trivy:latest
ARG GITLEAKS_IMAGE=zricethezav/gitleaks:latest
ARG SYFT_IMAGE=anchore/syft:latest
ARG GRYPE_IMAGE=anchore/grype:latest
ARG SEMGREP_IMAGE=semgrep/semgrep:latest
ARG BASE_IMAGE=alpine:latest
ARG TARGET_IMAGE

FROM ${REGISTRY}/${CLAMAV_IMAGE} AS clamav
FROM ${REGISTRY}/${TRIVY_IMAGE} AS trivy
FROM ${REGISTRY}/${GITLEAKS_IMAGE} AS gitleaks
FROM ${REGISTRY}/${SYFT_IMAGE} AS syft
FROM ${REGISTRY}/${GRYPE_IMAGE} AS grype
FROM ${REGISTRY}/${SEMGREP_IMAGE} AS semgrep

FROM ${REGISTRY}/${BASE_IMAGE} AS base
FROM ${REGISTRY}/${TARGET_IMAGE} AS target

FROM base AS base-stage
SHELL ["/bin/sh", "-o", "pipefail", "-c"]
WORKDIR /scanroot
COPY --from=target / /scanroot

FROM base-stage AS trivy-stage
ARG TRIVY_WORKDIR=.
ARG TRIVY_SEVERITY=CRITICAL,HIGH
ARG CACHEBUST
WORKDIR /reports
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY .trivyignore* /reports/
RUN echo "db refresh ${CACHEBUST:-}"; \
    IGN=""; [ -f .trivyignore.yaml ] && IGN="--ignorefile .trivyignore.yaml"; \
    trivy rootfs $IGN \
    --scanners vuln,secret,misconfig \
    --pkg-types os,library \
    --severity "$TRIVY_SEVERITY" \
    --exit-code 0 --no-progress \
    -f json -o trivy_report.json \
    "/scanroot/$TRIVY_WORKDIR"

FROM base-stage AS clamscan-stage
ARG CLAMAV_WORKDIR=.
WORKDIR /reports
ARG CACHEBUST
RUN apk add --no-cache clamav-libunrar clamav
COPY --from=clamav --chown=clamav /var/lib/clamav/ /var/lib/clamav/
COPY --chmod=0755 clamav_report_to_json.sh /usr/local/bin/clamav_report_to_json.sh
RUN echo "db refresh ${CACHEBUST:-}"; \
    freshclam --stdout || echo "WARNING: freshclam failed, using the DB shipped in the clamav image" >&2
RUN rc=0; \
    clamscan -r -i \
    --max-filesize=2000M --max-scansize=4000M \
    --alert-exceeds-max=yes --alert-encrypted=yes \
    --follow-dir-symlinks=0 --follow-file-symlinks=0 \
    "/scanroot/$CLAMAV_WORKDIR" > clamav_report.txt || rc=$?; \
    [ "$rc" -le 1 ] || exit "$rc"; \
    clamav_report_to_json.sh clamav_report.txt | tee clamav_report.json

FROM base-stage AS gitleaks-stage
ARG GITLEAKES_WORKDIR=.
WORKDIR /reports
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
RUN gitleaks dir "/scanroot/$GITLEAKES_WORKDIR" \
    --no-banner --redact \
    --report-format=json \
    --exit-code=0 \
    --report-path=gitleaks_report.json

FROM base-stage AS syft-stage
ARG SYFT_WORKDIR=.
WORKDIR /reports
COPY --from=syft /syft /usr/local/bin/syft
RUN syft scan "dir:/scanroot/$SYFT_WORKDIR" -o cyclonedx-json=syft_report.json

FROM base-stage AS grype-stage
WORKDIR /reports
COPY --from=grype /grype /usr/local/bin/grype
COPY --from=syft-stage /reports/syft_report.json .
ARG CACHEBUST
RUN echo "db refresh ${CACHEBUST:-}"; grype sbom:/reports/syft_report.json -o json --file grype_report.json

FROM semgrep AS semgrep-stage
ARG SEMGREP_WORKDIR=.
COPY --from=target / /scanroot
WORKDIR /reports
RUN semgrep scan --config p/default --metrics=off \
    --json --output semgrep_report.json "/scanroot/$SEMGREP_WORKDIR"

FROM scratch AS final-stage
WORKDIR /reports
COPY --from=clamscan-stage /reports/clamav_report.json .
COPY --from=trivy-stage /reports/trivy_report.json .
COPY --from=gitleaks-stage /reports/gitleaks_report.json .
COPY --from=syft-stage /reports/syft_report.json .
COPY --from=grype-stage /reports/grype_report.json .
COPY --from=semgrep-stage /reports/semgrep_report.json .
