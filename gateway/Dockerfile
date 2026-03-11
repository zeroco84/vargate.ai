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

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY execution_engine.py .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
