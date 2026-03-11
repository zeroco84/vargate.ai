  # Vargate — Hetzner Deployment Guide

Deploy Vargate to a Hetzner Cloud instance at **vargate.ai**.

All deployment files are checked into the repo — no manual file copying needed.

---

## 1. Hetzner Instance Setup

### Recommended instance
| Spec | Value |
|------|-------|
| **Type** | CX32 (4 vCPU, 8GB RAM) — minimum. CX42 (8 vCPU, 16GB RAM) if budget allows |
| **OS** | Ubuntu 24.04 LTS |
| **Location** | Nuremberg or Helsinki (EU — good for GDPR demo narrative) |
| **Networking** | Public IPv4 + IPv6 |
| **Backups** | Enable (~20% extra — worth it for a demo) |

> **Cost**: CX32 is ~€13/month. CX42 is ~€25/month.

### Create the instance
1. Log into [console.hetzner.com](https://console.hetzner.com)
2. New Project → "vargate"
3. Add Server → pick OS, type, region as above
4. Add your SSH public key during setup
5. Create server — note the public IP

---

## 2. DNS

Point your domain at the Hetzner IP. Let's Encrypt needs DNS to resolve first.

```
A    vargate.ai    →    <hetzner-ip>
AAAA vargate.ai    →    <hetzner-ipv6>   (optional)
```

Check propagation:
```bash
dig vargate.ai +short
```

---

## 3. Server Hardening

```bash
ssh root@<hetzner-ip>

apt update && apt upgrade -y

# Create a non-root user
adduser vargate
usermod -aG sudo vargate
rsync --archive --chown=vargate:vargate ~/.ssh /home/vargate/

# Disable root SSH
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd

# Firewall
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

Re-login as `vargate`:
```bash
ssh vargate@<hetzner-ip>
```

---

## 4. Install Docker

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
exit
# ssh vargate@<hetzner-ip> again

docker --version
docker compose version
```

---

## 5. Deploy

```bash
# Clone the repo
git clone https://github.com/your-org/vargate.git ~/vargate
cd ~/vargate

# Create .env from the example and set your Redis password
cp .env.example .env
nano .env
# Generate password: openssl rand -hex 32
# Paste it as REDIS_PASSWORD=<your-password>
```

That's it for file setup — everything else is already in the repo.

---

## 6. TLS Certificate (Let's Encrypt)

Get a certificate before starting the full stack:

```bash
# Step 1: Temporarily comment out the HTTPS server block in nginx/conf.d/vargate.conf
# (the 'server { listen 443 ...' block — leave the port 80 block)

# Step 2: Start nginx in HTTP-only mode
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d nginx

# Step 3: Get the certificate
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  --profile certbot run certbot certonly \
  --webroot \
  --webroot-path=/var/www/certbot \
  --email your@email.com \
  --agree-tos \
  --no-eff-email \
  -d vargate.ai

# Step 4: Uncomment the HTTPS server block in nginx/conf.d/vargate.conf

# Step 5: Restart nginx
docker compose -f docker-compose.yml -f docker-compose.prod.yml restart nginx
```

**Auto-renewal** — add to crontab:
```bash
crontab -e
# Add:
0 3 * * * cd ~/vargate && docker compose --profile certbot run certbot renew --quiet && docker compose exec nginx nginx -s reload
```

---

## 7. Start the Full Stack

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

# Watch logs
docker compose logs -f

# Check all 8 services are running
docker compose ps
```

---

## 8. Verify

```bash
curl https://vargate.ai/api/health
curl https://vargate.ai/api/audit/verify
open https://vargate.ai
```

---

## 9. Seed Demo Data

```bash
# On your local machine:
pip install requests
export VARGATE_URL=https://vargate.ai/api

python test_demo.py
python test_hotswap.py      # needs BUNDLE_URL or SSH tunnel (see note below)
python test_behavioral.py
```

> **Note**: `test_hotswap.py` calls the bundle server directly for live policy updates.
> In production the bundle server is internal-only. Either:
> - SSH tunnel: `ssh -L 8080:localhost:8080 vargate@vargate.ai`
> - Then: `export BUNDLE_URL=http://localhost:8080`

---

## 10. Operational Notes

```bash
# Safe stop (preserves volumes):
docker compose down

# NEVER use -v (destroys HSM keys, audit data):
docker compose down -v    # ← DESTRUCTIVE

# View logs:
docker compose logs gateway --tail=100 -f

# Update:
git pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

---

## 11. Instance Sizing

| Scenario | Instance |
|----------|----------|
| Light demos | CX22 (2 vCPU, 4GB) — ~€7/mo |
| Normal use | CX32 (4 vCPU, 8GB) — ~€13/mo |
| Sustained load | CX42 (8 vCPU, 16GB) — ~€25/mo |

---

## 12. Repo Structure (deployment files)

```
vargate/
├── docker-compose.yml          ← base (dev)
├── docker-compose.prod.yml     ← production overlay
├── .env.example                ← copy to .env, fill in REDIS_PASSWORD
├── nginx/
│   ├── nginx.conf              ← main nginx config
│   └── conf.d/
│       └── vargate.conf        ← TLS + /api/ proxy + dashboard
├── blockchain/
│   └── entrypoint.sh           ← production Hardhat entrypoint
└── ...
```

---

## Known Demo Limitations

1. **Hardhat is a local blockchain** — not Polygon/Arbitrum. Production would use a real network.
2. **SoftHSM2 is a software HSM** — not FIPS 140-2 Level 3. Crypto-shredding logic is correct; hardware is demo-grade.
3. **SQLite is not production persistence** — use PostgreSQL for a real deployment.
4. **No Merkle tree yet** — hash chaining is a component, not the full structure for AGCS AG-2.2/AG-2.3.

Frame as: "this is our working prototype validating the architecture."
