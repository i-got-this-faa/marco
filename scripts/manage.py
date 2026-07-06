#!/usr/bin/env python3
"""
Mail server management toolbox — wrap common admin tasks.

Commands:

  info          Print a summary of server state (users, domains, queue, stats)
  audit         Run the built-in audit and print results
  rotate-dkim   Rotate the DKIM signing key
  gen-key       Print a DKIM key pair (does not touch server config)
  flush-queue   Delete all pending queue items
  export-json   Dump the full server state as JSON

Environment:
  MARCO_API_URL       Admin API base URL (default http://localhost:8080)
  MARCO_API_TOKEN     Existing session token
  MARCO_ADMIN_EMAIL   Admin email (prompted if not set)
  MARCO_ADMIN_PASSWORD Admin password
"""

import argparse
import json
import sys
from datetime import datetime

from marco_api import MarcoAPI, MarcoError


def cmd_info(api: MarcoAPI, _args: argparse.Namespace) -> None:
    print(f"Marco Mail Server  —  {api.base_url}")
    print("=" * 50)

    try:
        h = api.health()
        print(f"  Health:     {h.get('status', '?')}  (v{h.get('version', '?')})")
    except MarcoError as e:
        print(f"  Health:     FAIL — {e}")

    users = api.list_users()
    print(f"  Users:      {len(users)}")

    domains = api.list_domains()
    print(f"  Domains:    {len(domains)}")
    for d in domains:
        print(f"               - {d}")

    aliases = api.list_aliases()
    print(f"  Aliases:    {len(aliases)}")

    queue = api.list_queue()
    print(f"  Queue:      {len(queue)} pending")

    stats = api.stats()
    print(f"  Messages:   {stats.get('messages', '?')}")


def cmd_audit(api: MarcoAPI, _args: argparse.Namespace) -> None:
    """Trigger the server's built-in audit and display results."""
    # The built-in audit runs server-side via `marco audit`.
    # This is a client-side approximation using the API.
    info = api.stats()
    health = api.health()
    users = api.list_users()
    domains = api.list_domains()
    queue = api.list_queue()

    print("Marco Admin API Audit")
    print("=" * 50)
    print(f"  API reachable:                {'PASS' if health.get('status') == 'ok' else 'FAIL'}")
    print(f"  Server version:               {health.get('version', '?')}")
    print(f"  Users:                        {len(users)}")
    print(f"  Domains:                      {len(domains)}")
    print(f"  Aliases:                      {len(api.list_aliases())}")
    print(f"  Pending queue:                {len(queue)}")
    print(f"  Messages stored:              {info.get('messages', '?')}")

    # Flag suspicious states.
    orphan_aliases = [a for a in api.list_aliases() if a.get("domain") not in domains]
    if orphan_aliases:
        print(f"  Aliases with missing domain:  WARN  ({len(orphan_aliases)})")

    print()
    print("To run the full server-side audit (config + DNS + DB):")
    print("  marco audit")


def cmd_rotate_dkim(api: MarcoAPI, _args: argparse.Namespace) -> None:
    result = api.rotate_dkim()
    print("DKIM key rotated successfully.")
    print()
    print("Publish this DNS TXT record:")
    print(f"  {result['dns_record']}")
    print()
    print(f"  Selector:  {result['selector']}")
    print(f"  Domain:    {result['domain']}")


def cmd_gen_key(args: argparse.Namespace) -> None:
    """Print a DKIM key pair (runs marco gen-key locally)."""
    import subprocess
    cmd = ["go", "run", "./cmd/marco", "gen-key"]
    if args.domain:
        cmd.append(args.domain)
    subprocess.run(cmd, check=True)


def cmd_flush_queue(api: MarcoAPI, _args: argparse.Namespace) -> None:
    items = api.list_queue()
    if not items:
        print("Queue already empty.")
        return

    confirmed = input(f"Delete all {len(items)} queued messages? [y/N] ")
    if confirmed.strip().lower() != "y":
        print("Aborted.")
        return

    deleted = 0
    for q in items:
        try:
            api.delete_queue_item(q["id"])
            deleted += 1
        except MarcoError as e:
            print(f"  FAIL  [{q['id']}] {e}", file=sys.stderr)
    print(f"Deleted {deleted}/{len(items)} queue items.")


def cmd_export_json(api: MarcoAPI, args: argparse.Namespace) -> None:
    state = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "url": api.base_url,
        "health": api.health(),
        "stats": api.stats(),
        "users": api.list_users(),
        "domains": api.list_domains(),
        "aliases": api.list_aliases(),
        "queue": api.list_queue(),
    }
    output = json.dumps(state, indent=2, default=str)
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"State exported to {args.output}")
    else:
        print(output)


def main() -> None:
    parser = argparse.ArgumentParser(description="Marco mail server management")
    parser.add_argument("--url", default=None)

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("info", help="Print server state summary")
    sub.add_parser("audit", help="Run client-side audit checks")
    sub.add_parser("rotate-dkim", help="Rotate DKIM signing key")

    p = sub.add_parser("gen-key", help="Print a DKIM key pair (runs go run ./cmd/marco gen-key)")
    p.add_argument("domain", nargs="?", default="example.com")

    sub.add_parser("flush-queue", help="Delete all pending queue items")

    p = sub.add_parser("export-json", help="Dump server state as JSON")
    p.add_argument("--output", "-o", help="Write to file instead of stdout")

    args = parser.parse_args()

    # Commands that don't need an API connection.
    if args.command == "gen-key":
        cmd_gen_key(args)
        return

    api = MarcoAPI(base_url=args.url).with_session()

    try:
        if args.command == "info":
            cmd_info(api, args)
        elif args.command == "audit":
            cmd_audit(api, args)
        elif args.command == "rotate-dkim":
            cmd_rotate_dkim(api, args)
        elif args.command == "flush-queue":
            cmd_flush_queue(api, args)
        elif args.command == "export-json":
            cmd_export_json(api, args)
    except MarcoError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
