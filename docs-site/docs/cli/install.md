# CLI Installation

The Vargate CLI (`vargate-cli`) lets you manage your governance proxy from the terminal.

---

## Prerequisites

- Python 3.10 or higher
- pip

---

## Install

```bash
pip install vargate-cli
```

Or install from source:

```bash
git clone https://github.com/zeroco84/vargate.ai.git
cd vargate.ai/cli
pip install -e .
```

---

## Setup

Run the init command to configure your API URL and key:

```bash
vargate init
```

You'll be prompted for:

1. **API URL** — defaults to `https://vargate.ai/api`
2. **API Key** — your tenant API key from signup or dashboard

Configuration is saved to `~/.vargate/config.json`:

```json
{
  "api_url": "https://vargate.ai/api",
  "api_key": "vg-abc123..."
}
```

---

## Verify Setup

Check that everything is connected:

```bash
vargate status
```

You should see gateway health, Redis status, blockchain connection, and Merkle tree count.

Then send a test action:

```bash
vargate test
```

This submits a test tool call and verifies it appears in the audit trail.

---

## Next Steps

See [Commands](commands.md) for the full command reference.
