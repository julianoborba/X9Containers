# sudo docker buildx build --network=host -t suspectimage \
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
#   .
# 
# sudo docker create --name suspectcontainer -it suspectimage /bin/sh
# sudo docker cp suspectcontainer:/reports ./reports
# sudo docker rm suspectcontainer
# 
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
WORKDIR /scanroot
COPY --from=target / /scanroot

FROM base-stage AS trivy-stage
ARG TRIVY_WORKDIR=.
ARG TRIVY_SEVERITY=CRITICAL,HIGH
WORKDIR /reports
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY .trivyignore.yaml /reports/.trivyignore.yaml
RUN trivy filesystem \
      --scanners vuln,secret,misconfig \
      --severity $TRIVY_SEVERITY \
      --exit-code 0 --no-progress \
      "/scanroot/$TRIVY_WORKDIR" \
      -f json -o trivy_report.json

FROM base-stage AS clamscan-stage
ARG CLAMAV_WORKDIR=.
WORKDIR /reports
RUN sed -i 's/dl-cdn.alpinelinux.org/dl-cdn.alpinelinux.org/g' /etc/apk/repositories && \
    echo "https://dl-cdn.alpinelinux.org/alpine/latest-stable/community" >> /etc/apk/repositories && \
    apk update && \
    apk upgrade && \
    apk add --no-cache clamav-libunrar clamav
COPY --from=clamav /var/lib/clamav/main.cvd /var/lib/clamav/
COPY --from=clamav /var/lib/clamav/daily.cvd /var/lib/clamav/
COPY --from=clamav /var/lib/clamav/bytecode.cvd /var/lib/clamav/
COPY clamav_report_to_json.sh /reports/clamav_report_to_json.sh
RUN freshclam
RUN clamscan \
      -r -i \
      "/scanroot/$CLAMAV_WORKDIR" \
      | ./clamav_report_to_json.sh | tee clamav_report.json

FROM base-stage AS gitleaks-stage
ARG GITLEAKES_WORKDIR=.
WORKDIR /reports
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
RUN gitleaks detect \
      --source="/scanroot/$GITLEAKES_WORKDIR" \
      --no-git \
      --report-format=json \
      --exit-code=0 \
      --report-path=gitleaks_report.json

FROM base-stage AS syft-stage
ARG SYFT_WORKDIR=.
WORKDIR /reports
COPY --from=syft /syft /usr/local/bin/syft
RUN syft "/scanroot/$SYFT_WORKDIR" -o cyclonedx-json | tee "syft_report.json"

FROM base-stage AS grype-stage
WORKDIR /reports
COPY --from=grype /grype /usr/local/bin/grype
COPY --from=syft-stage /reports/syft_report.json .
RUN grype sbom:"/reports/syft_report.json" -o json | tee "grype_report.json"

FROM base-stage AS semgrep-stage
ARG SEMGREP_WORKDIR=.
WORKDIR /reports
RUN apk add --no-cache python3 py3-pip
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir semgrep
RUN semgrep scan --config auto --json --output "semgrep_report.json" "/scanroot/$SEMGREP_WORKDIR"

FROM scratch AS final-stage
WORKDIR /reports
COPY --from=clamscan-stage /reports/clamav_report.json .
COPY --from=trivy-stage /reports/trivy_report.json .
COPY --from=gitleaks-stage /reports/gitleaks_report.json .
COPY --from=syft-stage /reports/syft_report.json .
COPY --from=grype-stage /reports/grype_report.json .
COPY --from=semgrep-stage /reports/semgrep_report.json .
