FROM python:3.12-slim

WORKDIR /app

# Install OPA binary for policy replay (ephemeral evaluation)
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && ARCH=$(dpkg --print-architecture) \
    && curl -L -o /usr/local/bin/opa "https://openpolicyagent.org/downloads/v1.4.2/opa_linux_${ARCH}_static" \
    && chmod +x /usr/local/bin/opa \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Sprint 16: install the shared vargate-audit-chain package (Apache 2.0)
# from the sibling packages/ directory. The build context is the repo
# root (see docker-compose.yml's `context: .` for the gateway service)
# so this path is relative to the repo root.
COPY packages/audit-chain /opt/audit-chain
RUN pip install --no-cache-dir /opt/audit-chain

COPY gateway/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY gateway/*.py .

RUN addgroup --system vargate && adduser --system --ingroup vargate vargate
RUN mkdir -p /data /backup && chown -R vargate:vargate /data /backup /app
USER vargate

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
