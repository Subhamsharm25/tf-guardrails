# tfguard has no third-party dependencies, so the image is the Python base plus ~40 KB of code.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
LABEL org.opencontainers.image.title="tf-guardrails" \
      org.opencontainers.image.description="Policy gate for Terraform plans on AWS, Azure and GCP" \
      org.opencontainers.image.source="https://github.com/Subhamsharm25/tf-guardrails" \
      org.opencontainers.image.licenses="MIT"
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin tfguard
WORKDIR /opt/tfguard
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . && rm -rf /opt/tfguard/src
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001
WORKDIR /work
ENTRYPOINT ["python", "-m", "tfguard"]
CMD ["--help"]
