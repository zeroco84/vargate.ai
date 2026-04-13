# Twitter / X Integration Guide

Vargate's Twitter integration enables governed posting and management of tweets through the proxy. All actions are logged to the audit trail, evaluated against OPA policy, and executed via brokered credentials (the agent never sees the Bearer token).

## Authentication

Twitter API v2 uses an OAuth 2.0 Bearer token for authentication. Register it in Vargate's HSM vault:

- **Tool ID:** `twitter`
- **Credential name:** `bearer_token`

To obtain a Bearer token:

1. Create a project at [developer.x.com](https://developer.x.com)
2. The free tier supports creating and deleting tweets
3. Copy the Bearer token from the project dashboard
4. Register it in Vargate via the UI (Settings > Vault Management) or API

## Tools

### vargate_twitter_create_tweet

Post a tweet on Twitter/X.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `text` | string | yes | Tweet text (max 280 characters) |

**Governance:** Requires human approval on GTM tenant (content review).

**Example:**
```json
{
  "tool": "twitter",
  "method": "create_tweet",
  "params": {
    "text": "We just open-sourced our agent governance framework. Check it out."
  }
}
```

**Response:**
```json
{
  "status": "tweet_created",
  "tweet_id": "1234567890123456789",
  "text": "We just open-sourced our agent governance framework. Check it out."
}
```

### vargate_twitter_delete_tweet

Delete a tweet by ID.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tweet_id` | string | yes | ID of the tweet to delete |

**Governance:** Requires human approval on GTM tenant (destructive action).

**Example:**
```json
{
  "tool": "twitter",
  "method": "delete_tweet",
  "params": { "tweet_id": "1234567890123456789" }
}
```

**Response:**
```json
{
  "status": "tweet_deleted",
  "tweet_id": "1234567890123456789",
  "deleted": true
}
```

### vargate_twitter_get_tweets

Get recent tweets for a user. Read-only.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `user_id` | string | yes | Twitter user ID |
| `max_results` | integer | no | Max tweets to return (default: 10) |

**Governance:** Allowed without human approval (read-only).

**Free tier limitation:** This endpoint requires the Twitter Basic plan ($100/mo). On the free tier it returns a clear error:
```json
{
  "error": "twitter_free_tier_limit",
  "status_code": 403,
  "detail": "Twitter free tier does not support reading tweets. Upgrade to the Basic plan ($100/mo) at developer.x.com to use this endpoint."
}
```

**Example:**
```json
{
  "tool": "twitter",
  "method": "get_user_tweets",
  "params": { "user_id": "123456789", "max_results": 5 }
}
```

**Response (Basic tier):**
```json
{
  "status": "ok",
  "tweets": [
    { "id": "1234567890123456789", "text": "Hello world" }
  ],
  "count": 1
}
```

## Governance Summary

| Tool | Method | GTM Approval Required |
|------|--------|-----------------------|
| `twitter` | `create_tweet` | Yes (content review) |
| `twitter` | `delete_tweet` | Yes (destructive) |
| `twitter` | `get_user_tweets` | No (read-only) |

## API Reference

Twitter API v2 endpoints used:

- **Create tweet:** `POST https://api.twitter.com/2/tweets`
- **Delete tweet:** `DELETE https://api.twitter.com/2/tweets/:id`
- **User tweets:** `GET https://api.twitter.com/2/users/:id/tweets` (Basic tier only)

All requests use `Authorization: Bearer <token>` header. See [Twitter API v2 documentation](https://developer.x.com/en/docs/twitter-api) for full details.
