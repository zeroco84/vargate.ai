# Twitter / X Integration

Vargate brokers Twitter/X on your behalf using **OAuth 2.0 (PKCE)**. Once
you connect, your governed agents can post tweets, follow users, send DMs,
read timelines, and more — with every action evaluated against your
policy and written to your audit log.

There's no code to edit and nothing to copy into a `.env` file. The whole
flow is a click-through wizard in your dashboard.

## Before you start

You'll need a **Twitter/X developer account** with an app configured for
OAuth 2.0. If you don't have one yet:

1. Go to [developer.x.com](https://developer.x.com) and sign in
2. Create a new Project and within it a new App
3. In the App settings → **User authentication settings** → click *Set up*
4. Select **OAuth 2.0** as the App type, turn on **OAuth 1.0a** only if you
   need the legacy fallback
5. App permissions: **Read, Write, and Direct Messages** (required for DMs)
6. Type of App: **Web App, Automated App or Bot**

Keep that browser tab open — you'll need to come back to enter the Callback
URL.

## Step 1 — Open the Vault Management panel

On your Vargate dashboard, open the **Vault Management** panel. In the
**Register New Credential** form, select **Twitter / X** from the Tool
dropdown.

You'll see:

- A **Callback URL** displayed prominently — this is unique to your
  deployment (e.g. `https://vargate.ai/api/oauth/twitter/callback`)
- A **Client ID** and **Client Secret** field
- A **Connect with Twitter** button
- A **Show legacy OAuth 1.0a** toggle (ignore unless you have a reason to
  use it)

## Step 2 — Register the callback URL in your Twitter app

Copy the callback URL from the Vault panel and paste it into your Twitter
app's **Callback URI / Redirect URL** list. You can add multiple — Vargate's
callback URL is the only one that will be used, so it's safe to add
alongside any others.

Save your Twitter app settings.

## Step 3 — Copy your Client ID and Client Secret

In the Twitter app settings, find **OAuth 2.0 Client ID and Client Secret**
(regenerate if you haven't seen them before — it'll only show the secret
once). Paste both into the Vargate form and click **Connect with Twitter**.

Vargate opens Twitter's consent page in a popup. Review the permissions
and approve. When you return to the Vargate tab, the credential will
appear in the **Registered Credentials** list as `twitter / oauth2`.

You're done — your agent can now call Twitter tools.

## What scopes Vargate requests

The default OAuth 2.0 scope set covers every Twitter tool we expose:

| Scope | Needed for |
|---|---|
| `tweet.read` | Reading tweets |
| `tweet.write` | Posting and deleting tweets |
| `users.read` | Resolving user profiles and IDs |
| `follows.read`, `follows.write` | Listing and changing follows |
| `dm.read`, `dm.write` | Reading and sending direct messages |
| `like.read`, `like.write` | Likes |
| `mute.read`, `mute.write` | Mute management |
| `offline.access` | Getting a refresh token so the proxy can stay authorised |

If any tool is missing from the list above, it's because we haven't
surfaced it as an MCP tool yet — not because the scope is missing.

## What your agent can do

Once connected, these MCP tools become callable (names as surfaced via
`tools/list`):

| Tool | Action |
|---|---|
| `vargate_twitter_create_tweet` | Post a tweet (≤280 chars) |
| `vargate_twitter_delete_tweet` | Delete one of your tweets |
| `vargate_twitter_get_tweets` | Read recent tweets for a user |
| `vargate_twitter_follow_user` | Follow another account |
| `vargate_twitter_unfollow_user` | Unfollow another account |
| `vargate_twitter_send_dm` | Send a direct message |
| `vargate_twitter_list_dm_conversations` | Read recent DM events |

By default every write operation (tweet, follow, DM) requires human
approval via your approval queue. You can relax any of those in
**Settings → Auto-Approve Rules** if you trust your policy to catch bad
content without a human in the loop.

## Token refresh

OAuth 2.0 access tokens expire after about 2 hours. Vargate handles this
automatically — it refreshes in the background whenever a tool call is
made with an expired or near-expired token, and rotates the stored
refresh token each time. There's no scheduled cron or maintenance needed
on your end.

If you revoke the app's access on Twitter's side (e.g. from
[account settings → Connected apps](https://twitter.com/settings/connected_apps)),
the refresh will fail on the next tool call and the audit log will record
a `twitter_oauth2_refresh_failed` error. Reconnect by clicking
**Connect with Twitter** again in Vault Management.

## Common issues

**"Popup blocked"** — allow popups for your Vargate dashboard domain and
retry. The OAuth flow can't work without being able to open Twitter's
consent page.

**"Callback URL mismatch"** — the URL in your Twitter app's whitelist
must match the one shown in the Vault panel exactly, including trailing
path segments. Copy-paste it, don't retype.

**"State token is invalid or expired"** — the OAuth flow has a 10-minute
window. If you took longer than that between clicking *Connect* and
approving on Twitter, just start again.

**DM returns 403** — the recipient either doesn't follow your account or
hasn't opened DMs to non-followers. This is a Twitter-side restriction,
not a policy block — your audit log will show `twitter_api_error` with
status 403.

**Tweet blocked with `gtm_blocked_phrase` or `gtm_explicit_content`** —
Vargate's content filter rejected the text. Tune the blocked phrase list
via your policy, or have the agent rephrase.

## Legacy OAuth 1.0a

If you already have OAuth 1.0a credentials registered (`twitter / api_key`),
tweets will continue to work on them. However, **DMs and follows require
OAuth 2.0** — OAuth 1.0a can't call those v2 endpoints. Connect via OAuth
2.0 to unlock the full tool set; the new `twitter / oauth2` credential is
automatically preferred over the legacy one.
