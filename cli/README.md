# vargate-cli

Command-line interface for the Vargate AI agent governance proxy.

## Install

```bash
cd cli/
pip install -e .
```

## Quick Start

```bash
# Configure API URL and key
vargate init

# Send a test governed action
vargate test

# Check gateway health
vargate status
```

## Commands

| Command | Description |
|---------|-------------|
| `vargate init` | Configure API URL and API key |
| `vargate status` | Show gateway and tenant health |
| `vargate test` | Send a test governed action and verify audit trail |
| `vargate audit` | View recent audit log entries (`--limit N`) |
| `vargate verify` | Verify hash chain integrity |
| `vargate replay <action_id>` | Replay a decision against current policy |

## Configuration

Config is stored in `~/.vargate/config.json` after running `vargate init`.

## Requirements

- Python 3.10+
- httpx
- rich
