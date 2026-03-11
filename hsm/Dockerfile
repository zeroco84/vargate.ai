FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    softhsm2 \
    opensc \
    libengine-pkcs11-openssl \
    python3-dev \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir python-pkcs11 fastapi uvicorn

WORKDIR /app
COPY hsm_service.py /app/hsm_service.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8300
ENTRYPOINT ["/entrypoint.sh"]
