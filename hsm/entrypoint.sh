#!/bin/bash
mkdir -p /var/lib/softhsm/tokens

# Initialise the token if it doesn't exist
if ! softhsm2-util --show-slots 2>/dev/null | grep -q "vargate-prototype"; then
    softhsm2-util --init-token --slot 0 \
        --label "vargate-prototype" \
        --pin 1234 \
        --so-pin 5678
    echo "[HSM] Token initialised: vargate-prototype"
else
    echo "[HSM] Token already exists: vargate-prototype"
fi

# Start the HSM API service
exec python /app/hsm_service.py
