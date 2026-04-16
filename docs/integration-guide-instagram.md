# Instagram Integration Guide

Vargate's Instagram integration enables governed publishing of posts through the proxy. All actions are logged to the audit trail, evaluated against OPA policy, and executed via brokered credentials (the agent never sees the access token).

## Authentication

Instagram's Content Publishing API uses **OAuth 2.0 access tokens** issued by the Meta (Facebook) Graph API platform. Only accounts that meet **all** of the following can publish via API:

- Instagram account type is **Business** or **Creator**
- The IG account is connected to a **Facebook Page**
- The app has been granted the `instagram_content_publish` permission

Register the credential in Vargate's HSM vault as a **JSON object**:

- **Tool ID:** `instagram`
- **Credential name:** `access_token`

**Credential value (JSON):**
```json
{
  "access_token": "long-lived-user-access-token",
  "ig_user_id": "17841..."
}
```

## Obtaining credentials

1. Create a Meta app at [developers.facebook.com](https://developers.facebook.com)
2. Add the **Instagram Graph API** product to the app
3. Link the Facebook Page that owns the IG Business/Creator account
4. In the Graph API Explorer, select your app and the page, and request these permissions:
   - `instagram_basic`
   - `instagram_content_publish`
   - `pages_show_list`
   - `pages_read_engagement`
5. Exchange the short-lived user access token for a **long-lived token** (60-day expiry):
   ```
   GET https://graph.facebook.com/v21.0/oauth/access_token
     ?grant_type=fb_exchange_token
     &client_id={app-id}
     &client_secret={app-secret}
     &fb_exchange_token={short-lived-token}
   ```
6. Find the IG user ID by calling:
   ```
   GET https://graph.facebook.com/v21.0/{page-id}?fields=instagram_business_account
   ```
   The returned `instagram_business_account.id` is the `ig_user_id`.
7. Paste the two values as a JSON object into the Vault Management credential field in the dashboard.

> Long-lived tokens last ~60 days and should be refreshed before expiry. A token-refresh workflow is not yet automated — set a reminder.

## Supported methods

### `create_post`

Publishes a single-image post.

**Params:**

| Field | Type | Notes |
|---|---|---|
| `image_url` | string | **Required.** Public HTTPS URL to a JPEG. Instagram fetches the image from this URL — file uploads are not supported. |
| `caption` | string | Optional. Up to 2,200 characters. |

Execution is a two-step Graph API flow:

1. `POST /{ig-user-id}/media` with `image_url`, `caption` → returns `creation_id`
2. `POST /{ig-user-id}/media_publish` with `creation_id` → returns `media_id`

**Success response:**
```json
{
  "status": "post_created",
  "media_id": "17895695668004550",
  "creation_id": "17884141045205025"
}
```

## Governance

All `instagram.create_post` calls for the GTM tenant are routed through the human-approval queue (see `policies/vargate/gtm_policy.rego`). The agent submits the action; a human reviewer approves or rejects it; the proxy only calls the Instagram API after approval.

## Platform limits

- **Rate limit:** 25 API-published posts per 24 hours per IG account
- **Caption:** 2,200 characters max, up to 30 hashtags, up to 20 mentions
- **Image formats:** JPEG. PNG and unsupported aspect ratios are rejected by Instagram
- **Media URL:** must be publicly reachable HTTPS; IG's fetcher does not follow redirects reliably

## MVP scope

This integration ships with single-image posts only. Video, carousel, reels, and stories use different container types and are not wired up yet.

## Disclosure

Sera's IG bio should disclose her AI nature, consistent with Vargate's AGCS self-governance posture and Meta's synthetic-media labeling expectations.
