"""
External uptime monitor for Vargate gateway.
Run on a separate server (e.g., rick@159.69.192.130) to detect full outages.
Do NOT run this inside the Vargate Docker stack — it must be external.

Usage:
    VARGATE_URL=https://vargate.ai/api/health \
    ALERT_EMAIL=rlarkin999@gmail.com \
    RESEND_API_KEY=re_xxx \
    python healthcheck.py
"""
import os, time, urllib.request, json

VARGATE_URL = os.getenv("VARGATE_URL", "https://vargate.ai/api/health")
CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "60"))
FAILURE_THRESHOLD = int(os.getenv("FAILURE_THRESHOLD", "3"))
ALERT_EMAIL = os.getenv("ALERT_EMAIL", "rlarkin999@gmail.com")
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")

consecutive_failures = 0
alert_sent = False

def check_health():
    if not VARGATE_URL.startswith(("http://", "https://")):
        print(f"[HEALTHCHECK] Failed: Invalid URL scheme in {VARGATE_URL}")
        return False

    try:
        req = urllib.request.Request(VARGATE_URL, method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            if resp.status == 200:
                return True
    except Exception as e:
        print(f"[HEALTHCHECK] Failed: {e}")
    return False

def send_alert(failures):
    if not RESEND_API_KEY:
        print(f"[HEALTHCHECK] ALERT: {failures} consecutive failures (no Resend key, email skipped)")
        return
    payload = json.dumps({
        "from": "Vargate Monitoring <alerts@vargate.ai>",
        "to": [ALERT_EMAIL],
        "subject": f"ALERT: Vargate gateway down ({failures} consecutive failures)",
        "text": f"The Vargate gateway at {VARGATE_URL} has failed {failures} consecutive health checks.\n\nCheck the production box immediately: ssh vargate@204.168.135.95",
    }).encode()
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=payload,
        headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=10)  # nosec B310
        print(f"[HEALTHCHECK] Alert email sent to {ALERT_EMAIL}")
    except Exception as e:
        print(f"[HEALTHCHECK] Failed to send alert: {e}")

def send_recovery():
    if not RESEND_API_KEY:
        print("[HEALTHCHECK] RECOVERY: Gateway is back up (no Resend key, email skipped)")
        return
    payload = json.dumps({
        "from": "Vargate Monitoring <alerts@vargate.ai>",
        "to": [ALERT_EMAIL],
        "subject": "RECOVERED: Vargate gateway is back up",
        "text": f"The Vargate gateway at {VARGATE_URL} has recovered.",
    }).encode()
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=payload,
        headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=10)  # nosec B310
        print("[HEALTHCHECK] Recovery email sent")
    except Exception:
        pass

if __name__ == "__main__":
    print(f"[HEALTHCHECK] Monitoring {VARGATE_URL} every {CHECK_INTERVAL}s (threshold: {FAILURE_THRESHOLD})")
    while True:
        if check_health():
            if alert_sent:
                send_recovery()
                alert_sent = False
            consecutive_failures = 0
            print("[HEALTHCHECK] OK")
        else:
            consecutive_failures += 1
            print(f"[HEALTHCHECK] FAIL ({consecutive_failures}/{FAILURE_THRESHOLD})")
            if consecutive_failures >= FAILURE_THRESHOLD and not alert_sent:
                send_alert(consecutive_failures)
                alert_sent = True
        time.sleep(CHECK_INTERVAL)
