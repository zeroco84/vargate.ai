"""
Vargate CLI — command-line interface for the Vargate AI agent governance proxy.

Commands:
    vargate init       Configure API URL and key
    vargate status     Show gateway and tenant health
    vargate test       Send a test governed action
    vargate audit      View recent audit log entries
    vargate verify     Verify hash chain integrity
    vargate replay     Replay a decision against current policy
"""

import argparse
import json
import os
import sys
from pathlib import Path

import httpx
from rich.console import Console
from rich.table import Table

console = Console()
CONFIG_DIR = Path.home() / ".vargate"
CONFIG_FILE = CONFIG_DIR / "config.json"


def _load_config() -> dict:
    if not CONFIG_FILE.exists():
        console.print("[red]Not configured. Run 'vargate init' first.[/red]")
        sys.exit(1)
    return json.loads(CONFIG_FILE.read_text())


def _client(config: dict) -> httpx.Client:
    return httpx.Client(
        base_url=config["api_url"],
        headers={"X-API-Key": config["api_key"]},
        timeout=30,
    )


def cmd_init(args):
    """Configure API URL and API key."""
    api_url = input(f"API URL [https://vargate.ai/api]: ").strip() or "https://vargate.ai/api"
    api_key = input("API Key: ").strip()
    if not api_key:
        console.print("[red]API key is required.[/red]")
        sys.exit(1)

    # Verify connectivity
    console.print(f"Connecting to {api_url}...", style="dim")
    try:
        r = httpx.get(f"{api_url}/health", timeout=10)
        r.raise_for_status()
        health = r.json()
        console.print(f"[green]Connected.[/green] Gateway status: {health['status']}")
    except Exception as e:
        console.print(f"[red]Connection failed: {e}[/red]")
        sys.exit(1)

    # Save config
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps({"api_url": api_url, "api_key": api_key}, indent=2))
    console.print(f"Config saved to {CONFIG_FILE}")

    # Show tenant info
    try:
        r = httpx.get(f"{api_url}/dashboard/me", headers={"X-API-Key": api_key}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            console.print(f"Tenant: [bold]{data.get('tenant_name', 'unknown')}[/bold] ({data.get('tenant_id', '')})")
    except Exception:
        pass


def cmd_status(args):
    """Show gateway and tenant health."""
    config = _load_config()
    with _client(config) as client:
        # Health
        r = client.get("/health")
        r.raise_for_status()
        health = r.json()

        table = Table(title="Gateway Status")
        table.add_column("Component", style="bold")
        table.add_column("Status")

        table.add_row("Gateway", f"[green]{health['status']}[/green]")
        table.add_row("Redis", "[green]OK[/green]" if health.get("redis") else "[red]DOWN[/red]")
        table.add_row("Blockchain", "[green]OK[/green]" if health.get("blockchain") else "[yellow]Disconnected[/yellow]")
        chains = ", ".join(health.get("connected_chains", [])) or "none"
        table.add_row("Chains", chains)
        table.add_row("Merkle Trees", str(health.get("merkle_tree_count", 0)))
        console.print(table)

        # Dashboard
        try:
            r = client.get("/dashboard/me")
            if r.status_code == 200:
                data = r.json()
                console.print(f"\nTenant: [bold]{data.get('tenant_name', '')}[/bold]")
                console.print(f"Chain length: {data.get('chain_length', 'N/A')}")
                console.print(f"Chain valid: {data.get('chain_valid', 'N/A')}")
        except Exception:
            pass


def cmd_test(args):
    """Send a test governed action."""
    config = _load_config()
    with _client(config) as client:
        console.print("Sending test tool call...", style="dim")
        r = client.post("/mcp/tools/call", json={
            "agent_id": "vargate-cli-test",
            "agent_type": "cli",
            "agent_version": "0.1.0",
            "tool": "http",
            "method": "GET",
            "params": {"url": "https://httpbin.org/get"},
        })

        if r.status_code == 200:
            data = r.json()
            console.print(f"[green]ALLOWED[/green] action_id={data['action_id']}")
            if data.get("execution_mode"):
                console.print(f"  Execution: {data['execution_mode']}")
        elif r.status_code == 403:
            data = r.json().get("detail", {})
            console.print(f"[red]DENIED[/red] action_id={data.get('action_id', 'N/A')}")
            console.print(f"  Violations: {data.get('violations', [])}")
            console.print(f"  Severity: {data.get('severity', 'N/A')}")
        elif r.status_code == 202:
            data = r.json()
            console.print(f"[yellow]PENDING APPROVAL[/yellow] action_id={data['action_id']}")
        else:
            console.print(f"[red]Error: HTTP {r.status_code}[/red]")
            console.print(r.text)
            return

        # Verify it appeared in the audit log
        console.print("\nVerifying audit trail...", style="dim")
        r2 = client.get("/audit/log", params={"limit": 1})
        if r2.status_code == 200:
            records = r2.json().get("records", [])
            if records:
                latest = records[0]
                console.print(f"Latest record: id={latest.get('id')} decision={latest.get('decision')} hash={latest.get('record_hash', '')[:16]}...")


def cmd_audit(args):
    """View recent audit log entries."""
    config = _load_config()
    limit = args.limit if hasattr(args, "limit") else 10
    with _client(config) as client:
        r = client.get("/audit/log", params={"limit": limit})
        r.raise_for_status()
        records = r.json().get("records", [])

        table = Table(title=f"Audit Log (last {limit})")
        table.add_column("ID", style="dim")
        table.add_column("Decision")
        table.add_column("Agent")
        table.add_column("Tool")
        table.add_column("Method")
        table.add_column("Severity")
        table.add_column("Hash", style="dim")

        for rec in records:
            decision = rec.get("decision", "")
            style = "green" if decision == "allow" else "red" if decision == "deny" else "yellow"
            table.add_row(
                str(rec.get("id", "")),
                f"[{style}]{decision}[/{style}]",
                rec.get("agent_id", "")[:20],
                rec.get("tool", ""),
                rec.get("method", ""),
                rec.get("severity", ""),
                rec.get("record_hash", "")[:16],
            )

        console.print(table)


def cmd_verify(args):
    """Verify hash chain integrity."""
    config = _load_config()
    with _client(config) as client:
        r = client.get("/audit/verify")
        r.raise_for_status()
        data = r.json()

        valid = data.get("valid", False)
        if valid:
            console.print(f"[green]CHAIN VALID[/green] — {data.get('record_count', 0)} records verified")
        else:
            console.print(f"[red]CHAIN BROKEN[/red] at record {data.get('broken_at', 'unknown')}")
            broken = data.get("broken_links", [])
            if broken:
                console.print(f"  Broken links: {broken}")


def cmd_replay(args):
    """Replay a decision against current policy."""
    config = _load_config()
    action_id = args.action_id
    with _client(config) as client:
        r = client.post("/audit/replay", json={"action_id": action_id})
        if r.status_code != 200:
            console.print(f"[red]Replay failed: {r.status_code}[/red]")
            console.print(r.text)
            return

        data = r.json()
        table = Table(title=f"Replay: {action_id}")
        table.add_column("", style="bold")
        table.add_column("Original")
        table.add_column("Replayed")

        orig = data.get("original", {})
        replayed = data.get("replayed", {})
        table.add_row("Decision", orig.get("decision", ""), replayed.get("decision", ""))
        table.add_row("Violations", str(orig.get("violations", [])), str(replayed.get("violations", [])))
        table.add_row("Severity", orig.get("severity", ""), replayed.get("severity", ""))

        match = data.get("match", False)
        table.add_row("Match", "[green]YES[/green]" if match else "[red]NO[/red]", "")
        console.print(table)


def app():
    parser = argparse.ArgumentParser(prog="vargate", description="Vargate AI governance CLI")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init", help="Configure API URL and key")
    sub.add_parser("status", help="Show gateway and tenant health")
    sub.add_parser("test", help="Send a test governed action")

    audit_p = sub.add_parser("audit", help="View recent audit log entries")
    audit_p.add_argument("--limit", type=int, default=10, help="Number of records")

    sub.add_parser("verify", help="Verify hash chain integrity")

    replay_p = sub.add_parser("replay", help="Replay a decision against current policy")
    replay_p.add_argument("action_id", help="Action ID to replay")

    args = parser.parse_args()

    commands = {
        "init": cmd_init,
        "status": cmd_status,
        "test": cmd_test,
        "audit": cmd_audit,
        "verify": cmd_verify,
        "replay": cmd_replay,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    app()
