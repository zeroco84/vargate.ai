# Substack Integration Guide

Vargate's Substack integration enables governed creation and management of Substack content through the proxy. All actions are logged to the audit trail, evaluated against OPA policy, and executed via brokered credentials (the agent never sees the Substack session cookie).

## Authentication

Substack uses a session cookie (`substack.sid`) for API access. The cookie is stored in Vargate's HSM vault under:

- **Tool ID:** `substack`
- **Credential name:** `substack_sid`

The `SUBSTACK_BASE_URL` environment variable must be set (e.g., `https://amisera.substack.com`).

## Posts (Long-Form)

### vargate_substack_create_post

Create a draft post on Substack. The post is created as a draft -- publishing requires a separate step in the Substack dashboard.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `title` | string | yes | Post title |
| `body` | string | yes | Post body (paragraphs separated by `\n\n`) |
| `is_newsletter` | boolean | no | `true` for newsletter, `false` for thread post (default) |

**Governance:** Requires human approval on GTM tenant (content review).

**Example:**
```json
{
  "tool": "substack",
  "method": "create_post",
  "params": {
    "title": "Why AI Governance Matters",
    "body": "First paragraph here.\n\nSecond paragraph here.",
    "is_newsletter": false
  }
}
```

**Response:**
```json
{
  "status": "draft_created",
  "draft_id": 193991948,
  "slug": "why-ai-governance-matters",
  "title": "Why AI Governance Matters",
  "edit_url": "https://amisera.substack.com/publish/post/193991948"
}
```

## Notes (Short-Form)

Substack Notes are short-form posts, similar to tweets. They support text content with optional link or image attachments.

### vargate_substack_create_note

Create a new Substack Note.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `body` | string | yes | Note text content |
| `attachment_url` | string | no | Link URL to attach |
| `attachment_image` | string | no | Image URL to attach |

**Governance:** Requires human approval on GTM tenant (content review).

**Example:**
```json
{
  "tool": "substack",
  "method": "create_note",
  "params": {
    "body": "Just published a new deep-dive on agent governance frameworks.",
    "attachment_url": "https://amisera.substack.com/p/why-ai-governance-matters"
  }
}
```

**Response:**
```json
{
  "status": "note_created",
  "note_id": 12345678,
  "body_preview": "Just published a new deep-dive on agent governance frameworks."
}
```

### vargate_substack_list_notes

List recent Substack Notes with pagination. Read-only -- no approval required.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `limit` | integer | no | Max notes to return (default: 20) |
| `offset` | integer | no | Pagination offset (default: 0) |

**Governance:** Allowed without human approval (read-only).

**Example:**
```json
{
  "tool": "substack",
  "method": "get_notes",
  "params": { "limit": 10 }
}
```

**Response:**
```json
{
  "status": "ok",
  "notes": [ ... ],
  "count": 10
}
```

### vargate_substack_delete_note

Delete a Substack Note by ID. Destructive action -- requires approval.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `note_id` | string | yes | ID of the Note to delete |

**Governance:** Requires human approval on GTM tenant (destructive action).

**Example:**
```json
{
  "tool": "substack",
  "method": "delete_note",
  "params": { "note_id": "12345678" }
}
```

**Response:**
```json
{
  "status": "note_deleted",
  "note_id": "12345678"
}
```

## Governance Summary

| Tool | Method | GTM Approval Required |
|------|--------|-----------------------|
| `substack` | `create_post` | Yes (content review) |
| `substack` | `create_note` | Yes (content review) |
| `substack` | `get_notes` | No (read-only) |
| `substack` | `delete_note` | Yes (destructive) |

## API Notes

Substack does not publish a public API. The endpoints used by this integration were confirmed via live testing (2026-04-12):

- **Posts:** `POST /api/v1/drafts` (publication subdomain)
- **Notes (create):** `POST /api/v1/comment/feed` (publication subdomain)
- **Notes (list):** `GET /api/v1/notes` (publication subdomain)
- **Notes (delete):** `DELETE /api/v1/comment/{id}` (publication subdomain)

Notes are internally stored as comments with `type: "feed"`. The body uses ProseMirror document format with `schemaVersion: "v1"`.

**CSRF:** POST and DELETE endpoints require an `Origin` header matching the publication URL. Without it, Substack returns 403.

These endpoints may change without notice. If requests start failing, inspect the Substack web app's network requests to confirm current endpoint paths.
