FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    softhsm2 \
    opensc \
    libengine-pkcs11-openssl \
    python3-dev \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY hsm_service.py /app/hsm_service.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8300
ENTRYPOINT ["/entrypoint.sh"]
