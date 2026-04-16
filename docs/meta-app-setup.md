# Meta App Setup for Instagram Integration

Step-by-step walkthrough for creating the Meta (Facebook) app that Vargate uses to publish to Instagram on Sera's behalf. Meta's UI moves around — call out gotchas are noted where they matter.

## Prerequisites

1. **Sera's IG account must be Creator (or Business).** In the IG app: Settings → Account → Switch to Professional Account → Creator.
2. **A Facebook Page is required.** Instagram's publishing API authenticates through a Page, not the IG account directly. Create one at [facebook.com/pages/create](https://facebook.com/pages/create) — pick a category like "Personal Blog" or "Public Figure."
3. **Link the IG account to the Page.** On the Page (Facebook desktop): Settings → Linked Accounts → Instagram → Connect. Sign in with Sera's IG credentials during this step.
4. **Facebook personal account.** The Meta app is owned by a Facebook user. Use a real account that controls the Page.

> Gotcha: if the IG→Page link is broken (common Meta bug), API calls return `instagram_business_account: null`. Relink if that happens.

## Phase 1 — Create the Meta app

1. Go to [developers.facebook.com](https://developers.facebook.com) → log in with the Facebook account that manages the Page.
2. Top-right **My Apps** → **Create App**.
3. **Use case** → "Other" → Next.
4. **App type** → "Business" → Next.
5. **App name**: `Vargate Sera IG` (or similar). Contact email: your address. **Business portfolio**: leave blank for now, it will prompt you later.
6. Click **Create app**. You'll land on the app dashboard.

## Phase 2 — Add Instagram Graph API

1. On the app dashboard, under **Add products to your app**, find **Instagram Graph API** → **Set up**.
2. You may also see "Instagram" and "Instagram Basic Display" — those are *different* products. Basic Display does **not** support publishing. You want **Graph API**.
3. Also add **Facebook Login for Business** (needed to authenticate and retrieve tokens).

## Phase 3 — Configure permissions

The token needs these permissions:

- `instagram_basic`
- `instagram_content_publish`
- `pages_show_list`
- `pages_read_engagement`

For your own testing (dev mode, posting to accounts you own), you get these **without app review**. Moving to production requires app review + business verification — not needed for Sera since you're posting to your own IG.

## Phase 4 — Get a user access token

1. Open the **Graph API Explorer**: [developers.facebook.com/tools/explorer](https://developers.facebook.com/tools/explorer).
2. Top-right: select your app from the **Meta App** dropdown.
3. Click **Generate Access Token**.
4. In the permissions picker, check:
   - `instagram_basic`, `instagram_content_publish`, `pages_show_list`, `pages_read_engagement`
5. A Facebook OAuth popup appears. Log in as Sera's controlling account, pick the Page Sera's IG is linked to, and grant the permissions.
6. You now have a **short-lived user access token** (~1–2 hour expiry) in the Explorer's token field. Copy it — call this `SHORT_LIVED_TOKEN`.

## Phase 5 — Exchange for a long-lived token (~60 days)

Get your **App ID** and **App Secret** from the app dashboard (Settings → Basic). Then:

```bash
curl -sS -G "https://graph.facebook.com/v21.0/oauth/access_token" \
  --data-urlencode "grant_type=fb_exchange_token" \
  --data-urlencode "client_id=YOUR_APP_ID" \
  --data-urlencode "client_secret=YOUR_APP_SECRET" \
  --data-urlencode "fb_exchange_token=SHORT_LIVED_TOKEN"
```

Response:
```json
{"access_token":"EAAG...","token_type":"bearer","expires_in":5183944}
```

`expires_in` is in seconds — ~60 days. This is your `LONG_LIVED_TOKEN`.

> Gotcha: never put `App Secret` anywhere it could leak (logs, chat, committed files). Run this in a terminal only.

## Phase 6 — Find the IG user ID

Two hops: get the Page ID, then the linked IG account ID.

```bash
# 1. List pages this token can manage
curl -sS "https://graph.facebook.com/v21.0/me/accounts?access_token=LONG_LIVED_TOKEN"
```

Find the Page Sera's IG is linked to. Copy its `id` — call this `PAGE_ID`.

```bash
# 2. Look up the IG business account attached to that Page
curl -sS "https://graph.facebook.com/v21.0/PAGE_ID?fields=instagram_business_account&access_token=LONG_LIVED_TOKEN"
```

Response:
```json
{"instagram_business_account":{"id":"17841412345678901"},"id":"PAGE_ID"}
```

That `instagram_business_account.id` is your `IG_USER_ID`.

## Phase 7 — Register in Vargate vault

In the dashboard: Vault Management → Tool: Instagram → paste:

- **Access Token:** `LONG_LIVED_TOKEN`
- **IG User ID:** `IG_USER_ID`

Click Register. The vault stores them as `{"access_token":"...","ig_user_id":"..."}` in the HSM.

## Phase 8 — Smoke test

With credentials registered, the first end-to-end test:

1. Host a test JPEG on any public HTTPS URL (public S3 bucket, Cloudinary, any static host).
2. Have Sera submit an `instagram.create_post` with `{image_url, caption}`.
3. Action lands in your approval queue.
4. You approve → proxy calls Graph API → you see `post_created` with a `media_id`, and the post appears on Sera's grid.

## Token refresh

Long-lived tokens expire in ~60 days. Refresh by re-running the Phase 5 exchange with the current long-lived token as `fb_exchange_token` — each refresh yields another 60 days. There's no automatic refresh in the proxy yet; set a calendar reminder for ~day 55.
