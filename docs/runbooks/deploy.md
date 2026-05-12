# Deploy runbook

How to ship changes to the three Vargate web surfaces. Everything in
this document was learned the hard way during the T4.5–T4.7.1
sprints; this is the canonical reference now.

> **Prod box:** `vargate@204.168.135.95`. SSH in as `root` to operate;
> prefix git/script work with `sudo -u vargate` (or use the `vg`
> alias) so file ownership stays consistent. **Never use `~`** in
> commands — it resolves differently for root vs. vargate. Always
> absolute paths.
>
> Repo paths on prod:
> - `/home/vargate/vargate` — Tyr backend (this repo: `zeroco84/vargate.ai`)
> - `/home/vargate/vargate-telemetry` — Ogma backend (`zeroco84/vargate-telemetry`)
> - `/home/vargate/vargate-frontend` — UI for both (`zeroco84/vargate-frontend`)

## Topology

| URL | What | Origin | Routed by |
|---|---|---|---|
| `https://vargate.ai/` | Marketing site (static) | `/var/www/vargate-marketing/` (host filesystem) | nginx vhost `vargate-host.conf` |
| `https://vargate.ai/api/` | Tyr backend gateway | `vargate-gateway-1` container | nginx → `127.0.0.1:8000` |
| `https://vargate.ai/dashboard/` | Tyr React dashboard | `vargate-ui-1` container | nginx → `127.0.0.1:3000` |
| `https://vargate.ai/grafana/` | Grafana | `vargate-grafana-1` container | nginx → `127.0.0.1:3001` |
| `https://ogma.vargate.ai/` | Ogma SPA (static build) | `/var/www/ogma-dashboard/` (host filesystem) | nginx vhost `ogma-vargate-ai.conf` |
| `https://ogma.vargate.ai/api/` | Ogma backend gateway | `vargate-telemetry-gateway-1` container | nginx → `127.0.0.1:8001` |
| `https://developer.vargate.ai/` | Docs site | `vargate-docs-1` container | nginx vhost `developer-vargate-host.conf` |

**Network model.** nginx runs **on the host**, not in Docker. It
reaches container backends via `127.0.0.1:<published-port>`. The
prod overlays in `docker-compose.prod.yml` are what publish those
ports; the dev compose files keep services on container-only
expose ports. Tyr's gateway publishes `127.0.0.1:8000`; Ogma's
gateway publishes `127.0.0.1:8001`.

**Cloudflare** sits in front of everything (orange-cloud DNS records
on the `vargate.ai` zone). Origin → Cloudflare edge → browser. Cache
purges are sometimes required after a deploy — see the per-site
sections.

**TLS.** Let's Encrypt via `certbot`, one cert per hostname stored at
`/etc/letsencrypt/live/<hostname>/`. Auto-renewal runs via the
`certbot.service` systemd unit fired by `certbot.timer` (twice a
day by default). See [Cert auto-renewal](#cert-auto-renewal) below
to verify it's healthy.

---

## Deploying the marketing site (`vargate.ai/`)

The marketing site is plain static HTML/CSS/JS plus a few image
assets. Source lives at the root of the `vargate-frontend` repo
(NOT under `apps/`). The eight allowlisted files are:

```
index.html  styles.css  script.js
vargate-logo.svg  vargate-wordmark.png  sera-avatar.png
AGCS-v0.9.pdf  favicon.png
```

### Deploy

After pushing changes to `origin/main`, on prod:

```bash
sudo -u vargate /home/vargate/vargate-frontend/scripts/deploy-marketing.sh
```

The script pulls origin/main, copies the allowlisted files into
`/var/www/vargate-marketing/`, chowns/chmods, reloads nginx, and
prints the live `<title>` (bypassing Cloudflare) as a sanity check.

### Cloudflare cache after a deploy

The nginx vhost sets 5-minute `Cache-Control` on HTML/CSS/JS and
30-day on images. Browsers and Cloudflare respect those, so a
deploy propagates to all clients within five minutes automatically.

**For an immediate flip** (copy change you want live now, or marketing
CTAs pointing somewhere new): purge in the Cloudflare dashboard:

> Caching → Configuration → Purge Cache → Custom URLs →
> `https://vargate.ai/`, `https://vargate.ai/index.html`

For hashed asset bundles (`/assets/index-XXXXX.js`) you never need
to purge — every build produces a new hash, so old Cloudflare cache
entries are simply abandoned, and the new HTML references the new
hash directly.

### Adding a new file to the marketing root

1. Add the file to `/home/vargate/vargate-frontend/` (repo root).
2. Add the filename to the `FILES=` array in
   `scripts/deploy-marketing.sh`.
3. Update the count language in `scripts/README.md`.
4. Commit, push, run `deploy-marketing.sh`.

**Do not** rsync the whole `vargate-frontend/` tree. The repo has
`apps/`, `packages/`, `node_modules/`, `.git/` etc. that absolutely
should not be in the public web root.

---

## Deploying the Ogma SPA (`ogma.vargate.ai/`)

Ogma is a Vite-built React SPA. Source at
`/home/vargate/vargate-frontend/apps/ogma-dashboard/`. Build output
goes to `dist/` and rsyncs to `/var/www/ogma-dashboard/`.

### Deploy

```bash
sudo -u vargate /home/vargate/vargate-frontend/scripts/deploy-ogma-dashboard.sh
```

The script:
1. `git pull --ff-only origin main`
2. `pnpm install --frozen-lockfile`
3. **Refuses to build** if neither `apps/ogma-dashboard/.env.production.local`
   nor the shell envs `VITE_GOOGLE_OAUTH_CLIENT_ID` /
   `VITE_MICROSOFT_OAUTH_CLIENT_ID` are present. Without these the
   SsoSignIn page bakes "SSO buttons are disabled" into the bundle.
4. `pnpm --filter @vargate/ogma-dashboard build` (Vite + OpenAPI
   codegen via the `prebuild` hook — requires the SSH deploy key for
   `vargate-telemetry` to be loaded into `ssh-agent`).
5. `rsync -a --delete dist/ /var/www/ogma-dashboard/` (`--delete`
   removes stale hashed assets).
6. `chown -R www-data:www-data` + `chmod -R 755`.
7. `nginx -t && systemctl reload nginx`.
8. Curls the local nginx with `Host: ogma.vargate.ai` and prints
   the live `<title>` for sanity.

### Cloudflare cache after a deploy

Same 5-minute discipline as the marketing site. For an immediate
flip:

> Caching → Configuration → Purge Cache → Custom URLs →
> `https://ogma.vargate.ai/`, `https://ogma.vargate.ai/index.html`

Hashed `/assets/*` files don't need purging.

### Common failure modes

- **"refusing to build — no Vite OAuth env"** — set up
  `apps/ogma-dashboard/.env.production.local` from the
  `.env.production.example` template. CLIENT_IDs are public; safe to
  ship in the bundle. See [OAuth callback URL maintenance](#oauth-callback-url-maintenance)
  for how to provision them.
- **"Permission denied (publickey)"** during the codegen step — the
  prebuild script clones `vargate-telemetry` for the OpenAPI YAML.
  Load the deploy key: `ssh-add /home/vargate/.ssh/vargate_telemetry_deploy`.
- **`/api/me` returns 404 not 401** — nginx isn't reaching the Ogma
  gateway. Confirm `127.0.0.1:8001` is bound (`ss -tnl | grep 8001`)
  and that the gateway container is healthy (`docker ps`).

---

## Deploying the Tyr dashboard (`vargate.ai/dashboard/`)

The Tyr dashboard is a Vite-built React app served from inside a
Docker container (`vargate-ui-1`). Source at
`/home/vargate/vargate/ui/`. The container's image bakes the build
output into nginx's html dir; deploys are a `docker compose build`.

### Deploy

```bash
cd /home/vargate/vargate
sudo -u vargate git pull origin main
docker compose -f /home/vargate/vargate/docker-compose.yml \
               -f /home/vargate/vargate/docker-compose.prod.yml \
               build ui
docker compose -f /home/vargate/vargate/docker-compose.yml \
               -f /home/vargate/vargate/docker-compose.prod.yml \
               up -d --force-recreate ui

# Confirm the new bundle hash is being served
curl -sk https://vargate.ai/dashboard/ | grep -oE 'index-[A-Za-z0-9_-]+\.js'
```

The hash changes every build — that's the cache buster. The matching
HTML references the new hash directly, so Cloudflare's old copies
of OLD asset names never bite.

### Path-prefix gotcha (`/dashboard/` vs `/`)

The Tyr SPA lives at `vargate.ai/dashboard/`, but the React code uses
absolute paths starting with `/` for assets. Browser resolves
`/foo.png` to `https://vargate.ai/foo.png` (apex), NOT
`https://vargate.ai/dashboard/foo.png`. The apex path hits the
**marketing** nginx, which serves from `/var/www/vargate-marketing/`
— not from the Tyr container.

There's a nginx carve-out for `/assets/` proxied to the Tyr container,
so Vite's bundle assets work. But any new static file in `ui/public/`
must either:

- Be referenced with an explicit `/dashboard/` prefix in the React
  source (e.g., `<img src="/dashboard/vargate-wordmark-white.png">`)
- **Or** be duplicated into `/var/www/vargate-marketing/` so the
  apex-relative path resolves correctly.

The Vite-clean fix is to set `base: '/dashboard/'` in
`ui/vite.config.js` so the build emits prefixed paths automatically.
Not yet done (touches the nginx `/assets/` carve-out and React Router
basename — its own change).

### Cloudflare cache after a deploy

Hashed asset bundles never need purging. The HTML at `/dashboard/`
inherits Cloudflare heuristic caching (~4 hours when no explicit
`Cache-Control` is set). For an immediate flip:

> Caching → Configuration → Purge Cache → Custom URLs →
> `https://vargate.ai/dashboard/`,
> `https://vargate.ai/dashboard/index.html`

### Common failure modes

- **`/dashboard/` shows old code after rebuild** — Cloudflare cached
  the HTML pointing at the OLD asset hash. Purge the URLs above, or
  test in incognito for definitive proof.
- **Logo / image broken in incognito** — almost certainly the
  path-prefix gotcha above. Open DevTools, check the IMG `src` — if
  it's `/something.png` without `/dashboard/`, that's the bug.
- **GitHub OAuth button missing** — by design when
  `GITHUB_CLIENT_ID` is unset. The React app probes
  `/api/auth/github` on mount; if the backend returns 501, the
  button hides. Set the env vars (see below), recreate the gateway,
  the button auto-reappears on next page load.

---

## nginx vhost source-of-truth

The repo source of truth is `/home/vargate/vargate/nginx/conf.d/`:

```
nginx/conf.d/vargate-host.conf            # vargate.ai (apex)
nginx/conf.d/ogma-vargate-ai.conf         # ogma.vargate.ai
nginx/conf.d/developer-vargate-host.conf  # developer.vargate.ai
```

**Critical:** these are NOT symlinked into `/etc/nginx/conf.d/`. They
are **manually copied**. After editing a vhost in the repo:

```bash
sudo -u vargate git -C /home/vargate/vargate pull origin main
sudo cp /home/vargate/vargate/nginx/conf.d/<filename>.conf /etc/nginx/conf.d/
sudo nginx -t && sudo systemctl reload nginx
```

The drift between `repo/nginx/conf.d/` and `/etc/nginx/conf.d/` is a
known foot-gun. A future improvement is to add a `deploy-nginx.sh`
script that does the copy + reload as one command.

---

## Adding a new subdomain (Cloudflare + cert + vhost)

Used when launching a new product surface. The Ogma deploy (T4.5.5)
followed this pattern; the eventual Tyr migration to
`tyr.vargate.ai` will too.

### 1. DNS (Cloudflare dashboard)

> vargate.ai zone → DNS → Add record:
> - **Type:** A
> - **Name:** `<subdomain>` (e.g., `tyr`)
> - **IPv4:** `204.168.135.95`
> - **Proxy status:** Proxied (orange cloud) — matches the rest of
>   the zone.
> - TTL: Auto

Wait ~30s, verify: `dig +short <subdomain>.vargate.ai` resolves
(returns a Cloudflare edge IP).

### 2. Stub HTTP-only nginx vhost (so certbot can do the ACME challenge)

`certbot --nginx` runs `nginx -t` before issuing the cert, and
`nginx -t` fails if the vhost references an `ssl_certificate` file
that doesn't exist yet. Break the cycle with a temporary HTTP-only
stub:

```bash
sudo tee /etc/nginx/conf.d/<subdomain>-vargate-ai.conf > /dev/null <<'EOF'
server {
    listen 80;
    server_name <subdomain>.vargate.ai;
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    location / {
        return 301 https://$host$request_uri;
    }
}
EOF
sudo mkdir -p /var/www/certbot
sudo nginx -t && sudo systemctl reload nginx
```

### 3. Cert via webroot challenge

```bash
sudo certbot certonly --webroot -w /var/www/certbot -d <subdomain>.vargate.ai
```

Cert lands at `/etc/letsencrypt/live/<subdomain>.vargate.ai/`. Auto-
renewal picks it up automatically — see [Cert auto-renewal](#cert-auto-renewal).

### 4. Replace the stub with the real vhost

Author the full vhost in `/home/vargate/vargate/nginx/conf.d/<subdomain>-vargate-ai.conf`
(use `ogma-vargate-ai.conf` as a template), commit + push, then on
prod:

```bash
sudo -u vargate git -C /home/vargate/vargate pull origin main
sudo cp /home/vargate/vargate/nginx/conf.d/<subdomain>-vargate-ai.conf /etc/nginx/conf.d/
sudo nginx -t && sudo systemctl reload nginx

# Smoke check
curl -sIk https://<subdomain>.vargate.ai/ | head -3
```

---

## Cert auto-renewal

Let's Encrypt certs are valid for 90 days. Renewal is automated.

### Verify the renewal job is alive

```bash
# Systemd timer that fires twice a day
systemctl list-timers certbot.timer

# Expect a NEXT line in the next ~12 hours and a recent LAST
```

### Inspect current certs

```bash
sudo certbot certificates

# For each one, expect:
#   Expiry Date: <future-date> (VALID: N days)
#   Certificate Name + Domains listed
```

If a cert is `< 30 days` from expiry and the timer hasn't renewed
it, something's wrong. Common causes:
- nginx isn't reachable on port 80 from the public internet
  (Cloudflare orange-cloud is fine; certbot uses webroot which
  resolves via the configured DNS, not direct origin IP)
- `/var/www/certbot/` isn't world-readable for the ACME challenge
- The vhost dropped its `/.well-known/acme-challenge/` location block

### Force a renewal test (dry-run)

```bash
sudo certbot renew --dry-run
```

Runs the full renewal protocol against Let's Encrypt's staging
servers — no real cert changes — and reports per-cert success or
failure. Run this **once a quarter** as a check that nothing's
silently broken.

### What lives where

| Cert | Domains | Used by |
|---|---|---|
| `/etc/letsencrypt/live/vargate.ai/` | vargate.ai | `vargate-host.conf` (marketing + dashboard + api + grafana) |
| `/etc/letsencrypt/live/ogma.vargate.ai/` | ogma.vargate.ai | `ogma-vargate-ai.conf` |
| `/etc/letsencrypt/live/developer.vargate.ai/` | developer.vargate.ai | `developer-vargate-host.conf` |

---

## OAuth callback URL maintenance

The product currently uses three OAuth providers across two surfaces:

| Provider | Surface | Callback URL | Where to manage |
|---|---|---|---|
| GitHub | Tyr (`vargate.ai/dashboard/`) | `https://vargate.ai/api/auth/github/callback` | https://github.com/settings/developers |
| Google | Ogma (`ogma.vargate.ai/`) | `https://ogma.vargate.ai/auth/callback/google` | https://console.cloud.google.com → APIs & Services → Credentials → OAuth 2.0 Client |
| Microsoft | Ogma (`ogma.vargate.ai/`) | `https://ogma.vargate.ai/auth/callback/microsoft` | https://portal.azure.com → Microsoft Entra ID → App registrations → Authentication |

### Provider credentials live in TWO places

**`CLIENT_ID`** values are **public** — they ship in the browser
bundle (Ogma) or are emitted on the auth-URL query string (Tyr).
They live in:

- `/home/vargate/vargate-telemetry/.env` as `GOOGLE_OAUTH_CLIENT_ID`,
  `MICROSOFT_OAUTH_CLIENT_ID` (Ogma backend gateway)
- `/home/vargate/vargate/.env` as `GITHUB_CLIENT_ID` (Tyr backend gateway)
- `/home/vargate/vargate-frontend/apps/ogma-dashboard/.env.production.local`
  as `VITE_GOOGLE_OAUTH_CLIENT_ID`, `VITE_MICROSOFT_OAUTH_CLIENT_ID`
  (Ogma frontend Vite build — baked into the JS bundle)

**`CLIENT_SECRET`** values are **server-side only**. They live ONLY in:

- `/home/vargate/vargate-telemetry/.env` (Ogma)
- `/home/vargate/vargate/.env` (Tyr)

Never put a SECRET in the frontend `.env.production.local` or any
file that ships in the browser bundle.

### Adding a new redirect URI (e.g., for a new subdomain)

When a new origin needs to support sign-in, you must add the matching
callback URL **in the provider's console**. The agent / backend can't
do this — it's a UI-only step in each provider.

For Google:

> Google Cloud Console → your project → APIs & Services →
> Credentials → click the OAuth 2.0 Client → "Authorized redirect
> URIs" → Add URI → Save

For Microsoft:

> Azure portal → Microsoft Entra ID → App registrations → your app
> → Authentication → "Web" → Redirect URIs → Add URI → Save

For GitHub:

> github.com/settings/developers → your OAuth app → "Authorization
> callback URL" → edit → Update application

If you skip this step, sign-in fails with `redirect_uri_mismatch`
(Google/Microsoft) or `The redirect_uri ... is not associated with
this application` (GitHub). The URL in the provider must match
EXACTLY — scheme, host, path, trailing slash all matter.

### Verifying the env actually landed on the container

```bash
# Ogma
docker exec vargate-telemetry-gateway-1 env | \
  grep -E "^GOOGLE_|^MICROSOFT_|^OGMA_OAUTH" | \
  sed 's/SECRET=.*/SECRET=[REDACTED]/'

# Tyr
docker exec vargate-gateway-1 env | \
  grep -E "^GITHUB_" | \
  sed 's/SECRET=.*/SECRET=[REDACTED]/'
```

If a value is empty (e.g., `MICROSOFT_OAUTH_CLIENT_ID=`), the gateway
hasn't picked it up. Two causes:
1. The `.env` doesn't have it. Add the line.
2. The `.env` has it, but the container was started before the line
   was added. `docker compose ... up -d --force-recreate gateway`
   to make the container re-read the env file.

---

## Future: Tyr migration to `tyr.vargate.ai`

The pattern matches T4.5.5 (Ogma migration). Sketch of the work:

1. **DNS + cert + nginx vhost** for `tyr.vargate.ai` per
   [Adding a new subdomain](#adding-a-new-subdomain-cloudflare--cert--vhost) above.
2. **Publish Tyr's gateway on a new host port** — currently it uses
   `127.0.0.1:8000` because that's the path nginx's apex vhost
   targets. A `tyr.vargate.ai` vhost can keep using `:8000` since
   the apex would also stop using it.
3. **Build Tyr's React app for the new origin.** This is where
   the `/dashboard/` path-prefix gotcha (described above) becomes
   moot — at the new origin the SPA is at `/`, so its absolute
   `<img src="/foo.png">` paths resolve correctly without any
   carve-outs.
4. **Update GitHub OAuth callback URL** to
   `https://tyr.vargate.ai/api/auth/github/callback` (or add it as
   a second authorized URL during transition).
5. **Update marketing CTAs** — the "Sign in" link currently points
   at `/dashboard/`; it'd point at `https://tyr.vargate.ai/` post-
   migration.
6. **Cookie isolation property is the load-bearing reason** —
   same as Ogma. A subdomain gives clean cookie scoping between
   the two products' sessions; a subpath would not.
7. **Transition period**: keep `/dashboard/` serving the old
   surface for a few weeks with a banner pointing users at the
   new URL. Eventually retire the `/dashboard/` proxy block from
   `vargate-host.conf`.

Don't try this until there's a real reason — current `/dashboard/`
works, and the migration touches every existing customer's
bookmarks / sessions.

---

## Quick reference: full deploy of all three surfaces

After a multi-repo push that touches everything:

```bash
# Marketing (vargate-frontend root files)
sudo -u vargate /home/vargate/vargate-frontend/scripts/deploy-marketing.sh

# Tyr dashboard (vargate/ui)
cd /home/vargate/vargate
sudo -u vargate git pull origin main
docker compose -f /home/vargate/vargate/docker-compose.yml \
               -f /home/vargate/vargate/docker-compose.prod.yml \
               build ui
docker compose -f /home/vargate/vargate/docker-compose.yml \
               -f /home/vargate/vargate/docker-compose.prod.yml \
               up -d --force-recreate ui

# Ogma SPA (vargate-frontend/apps/ogma-dashboard)
sudo -u vargate /home/vargate/vargate-frontend/scripts/deploy-ogma-dashboard.sh

# Backend changes (if any) — Tyr
cd /home/vargate/vargate
docker compose -f /home/vargate/vargate/docker-compose.yml \
               -f /home/vargate/vargate/docker-compose.prod.yml \
               up -d --force-recreate gateway

# Backend changes (if any) — Ogma
cd /home/vargate/vargate-telemetry
sudo -u vargate git pull origin main
docker compose -f /home/vargate/vargate-telemetry/docker-compose.yml \
               -f /home/vargate/vargate-telemetry/docker-compose.prod.yml \
               up -d --force-recreate gateway

# Smoke checks
curl -sIk https://vargate.ai/             | grep -i HTTP
curl -sIk https://vargate.ai/dashboard/   | grep -i HTTP
curl -sIk https://ogma.vargate.ai/        | grep -i HTTP
curl -s   https://ogma.vargate.ai/api/me  # expect 401 unauthenticated, NOT 404
```

If any of those return 404, 502, or an unexpected status, check
the matching nginx vhost is loaded (`nginx -t`) and the matching
container is healthy (`docker ps --filter health=healthy`).
