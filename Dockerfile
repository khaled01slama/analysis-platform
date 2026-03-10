# ═══════════════════════════════════════════════════════════════════════
#  Security Analysis Platform – Full Docker Image
#  Components: FastAPI API, Frontend, SBOM Analyzer, Correlation Engine,
#              Security Assistant, Vanir (Bazel-built), Joern CLI
# ═══════════════════════════════════════════════════════════════════════

# ---------- stage 1: build Vanir with Bazel ----------------------------
FROM eclipse-temurin:11-jdk AS vanir-builder

# Bazel & build essentials
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl gnupg git python3 python3-pip build-essential zip unzip && \
    curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor -o /usr/share/keyrings/bazel-archive-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg] https://storage.googleapis.com/bazel-apt stable jdk1.8" \
        > /etc/apt/sources.list.d/bazel.list && \
    apt-get update && apt-get install -y bazel && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /vanir-src
COPY vanir/vanir/ .

# Build the detector_runner binary (self-contained Python zip)
RUN bazel build //:detector_runner --build_python_zip -c opt 2>&1 || true
# The built binary ends up in bazel-bin/
# Copy it to a well-known location for the final image
RUN mkdir -p /vanir-dist && \
    cp -r bazel-bin/detector_runner /vanir-dist/ 2>/dev/null || true && \
    cp -r bazel-bin/detector_runner.zip /vanir-dist/ 2>/dev/null || true


# ---------- stage 2: runtime image ------------------------------------
FROM python:3.11-slim

LABEL maintainer="Security Analysis Platform"
LABEL description="All-in-one: FastAPI API + Frontend + SBOM Analyzer + Correlation Engine + Security Assistant + Vanir + Joern"

# ── Environment ─────────────────────────────────────────────────────
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Vanir
    VANIR_PATH=/opt/vanir \
    # Joern
    JOERN_HOME=/opt/joern \
    PATH="/opt/joern/joern-cli/bin:/opt/vanir:${PATH}" \
    # App
    HOST=0.0.0.0 \
    PORT=8000 \
    WORKERS=1

# ── System packages (Java for Joern, git for Vanir) ────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        openjdk-17-jre-headless \
        curl wget git gcc libffi-dev procps \
    && rm -rf /var/lib/apt/lists/*

# ── Install Joern CLI ──────────────────────────────────────────────
ARG JOERN_VERSION=v4.0.145
RUN mkdir -p /opt/joern && \
    cd /opt/joern && \
    curl -fsSL "https://github.com/joernio/joern/releases/download/${JOERN_VERSION}/joern-install.sh" -o joern-install.sh && \
    chmod +x joern-install.sh && \
    bash joern-install.sh --install-dir=/opt/joern/joern-cli && \
    rm -f joern-install.sh && \
    # Verify
    joern --version || true

# ── Copy pre-built Vanir from stage 1 ─────────────────────────────
COPY --from=vanir-builder /vanir-dist/ /opt/vanir/
# Also include the raw Vanir Python sources (for direct Python import)
COPY vanir/vanir/vanir/ /opt/vanir/vanir-src/vanir/
COPY vanir/vanir/requirements.txt /opt/vanir/vanir-src/requirements.txt
RUN pip install --no-cache-dir -r /opt/vanir/vanir-src/requirements.txt

WORKDIR /app

# ── Python deps (cached layer) ────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Copy application source ───────────────────────────────────────
COPY api/             api/
COPY correlation_engine/ correlation_engine/
COPY sbom_analyzer/   sbom_analyzer/
COPY security_assistant/ security_assistant/
COPY detection_script/ detection_script/
COPY frontend/        frontend/
COPY start.sh         start.sh
COPY docker-entrypoint.sh docker-entrypoint.sh

# ── Data dirs & permissions ────────────────────────────────────────
RUN mkdir -p data/uploads data/reports && \
    chmod +x start.sh docker-entrypoint.sh detection_script/*.sh

EXPOSE 8000

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["serve"]
