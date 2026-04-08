#!/usr/bin/env bash
# Install nightly backup cron job (run once on host)
set -euo pipefail
CRON_LINE="0 3 * * * /root/vargate-proxy/scripts/backup.sh >> /var/log/vargate-backup.log 2>&1"
(crontab -l 2>/dev/null | grep -v 'vargate.*backup'; echo "$CRON_LINE") | crontab -
echo "Cron installed: nightly backup at 03:00 UTC"
