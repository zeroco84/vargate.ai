# CLI Commands

Complete reference for all `vargate` CLI commands.

---

## `vargate init`

Configure API URL and API key. Interactive prompts save to `~/.vargate/config.json`.

```bash
$ vargate init
Vargate API URL [https://vargate.ai/api]: https://vargate.ai/api
API Key: vg-abc123...
Configuration saved to ~/.vargate/config.json
```

---

## `vargate status`

Show gateway health, tenant info, and chain status.

```bash
$ vargate status
Gateway Health
  Status:     ok
  Redis:      connected
  Blockchain: connected (polygon)
  Merkle:     11 trees

Tenant Info
  ID:         my-tenant
  Name:       My Company
  Rate Limit: 10 rps / 20 burst
```

---

## `vargate test`

Send a test governed action and verify it's recorded in the audit trail.

```bash
$ vargate test
Sending test action...
  Tool:     http
  Method:   GET
  Result:   allowed
  Action:   550e8400-e29b-41d4-a716-446655440000

Verifying audit trail...
  Record found in audit log
  Chain integrity: valid (128 records)
```

This is the fastest way to verify your integration is working end-to-end.

---

## `vargate audit`

View recent audit log entries.

```bash
$ vargate audit
$ vargate audit --limit 50
```

```
ID    Decision  Agent            Tool       Method          Severity
----  --------  ---------------  ---------  --------------  --------
128   allow     my-agent-v1      http       GET             none
127   deny      my-agent-v1      stripe     create_transfer high
126   allow     my-agent-v1      gmail      send_email      none
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--limit N` | 20 | Number of records to show |

---

## `vargate verify`

Check hash chain integrity.

```bash
$ vargate verify
Chain Integrity
  Status:  valid
  Records: 128
```

If the chain is broken:

```bash
$ vargate verify
Chain Integrity
  Status:  INVALID
  Broken at: action 550e8400-...
  Reason: hash_mismatch
```

---

## `vargate replay <action_id>`

Replay a historical decision against the current policy.

```bash
$ vargate replay 550e8400-e29b-41d4-a716-446655440000
Decision Replay
  Action:    550e8400-...
  Original:  allow
  Replay:    allow
  Consistent: yes
```

Use this to detect policy drift — whether today's policy would make the same decision as the original.
