# The decision layer (E4, M15).
#
# Copyright (c) 2026 Ekrami-Labs. All rights reserved.
#
# Two properties this image is built for, both from the playbook (§9):
#
#   * It runs offline. No model is baked in and none is fetched; the LLM is
#     reached over the network at a URL the site supplies, or the deployment
#     runs LLM_PROVIDER=echo and works with no model at all.
#   * The decision store is a volume, never a layer. A container that carries
#     its own database loses every decision, correction and receipt the moment
#     it is redeployed.
FROM python:3.13-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first, so a code change does not re-resolve the tree.
COPY orchestrator/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY orchestrator/ /app/
COPY VERSION /VERSION

# Unprivileged, and owning only what it must write. The decision layer holds
# credentials for an EDR and a firewall; root inside the container is one
# escape away from holding them outside it.
RUN useradd --system --uid 10001 --home /app aosoc \
    && mkdir -p /data /app/data \
    && chown -R aosoc:aosoc /app /data
USER aosoc

# Everything derived lives on the volume: the database, the response receipts,
# the case-sync directories and the backups.
ENV ORCHESTRATOR_DB_FILE=/data/soc_matrix.db \
    SOAR_LOG_FILE=/data/soar-actions.jsonl \
    CASE_SYNC_DIR=/data/case-sync \
    BACKUP_DIR=/data/backups \
    BROKER_PORT=8500
VOLUME ["/data"]

EXPOSE 8500

# Liveness only — /health answers unauthenticated with ok/service/version and
# reveals the deployment's configuration only to a key holder.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8500/health', timeout=4).status == 200 else 1)"

CMD ["uvicorn", "soc_orchestrator:app", "--host", "0.0.0.0", "--port", "8500"]
