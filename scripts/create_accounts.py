#!/usr/bin/env python3
"""
Bulk account creation and management for testing.

Facilities:
  - Create a single user
  - Bulk-create users from a JSON file, CSV, or a simple pattern
  - Create users + domains + aliases in one shot
  - Reset (delete all users, domains, aliases) for a clean test state
  - Generate random-ish credentials with configurable domain

Usage:
  export MARCO_API_URL=http://localhost:8080
  export MARCO_ADMIN_EMAIL=admin@example.com
  export MARCO_ADMIN_PASSWORD=admin1234

  # Quick test user
  python scripts/create_accounts.py one --email tester@example.com --password test1234

  # Bulk from a CSV
  python scripts/create_accounts.py csv --file users.csv

  # Bulk generated
  python scripts/create_accounts.py generate --count 10 --domain example.com

  # Full setup (domain + users + alias) from a JSON manifest
  python scripts/create_accounts.py manifest --file setup.json

  # Clean slate
  python scripts/create_accounts.py reset --keep admin@example.com
"""

import argparse
import csv
import json
import random
import string
import sys
import time
from typing import Any

from marco_api import MarcoAPI, MarcoError


# ------------------------------------------------------------------
# Generators
# ------------------------------------------------------------------

def random_password(length: int = 12) -> str:
    """Generate a random ASCII password (letters + digits)."""
    chars = string.ascii_letters + string.digits
    return "".join(random.choices(chars, k=length))


def random_username(index: int, prefix: str = "test") -> str:
    return f"{prefix}.user{index}"


# ------------------------------------------------------------------
# Actions
# ------------------------------------------------------------------

def cmd_one(api: MarcoAPI, args: argparse.Namespace) -> None:
    """Create a single user."""
    password = args.password or random_password()
    api.create_user(args.email, password)
    print(f"  Created  {args.email}  password={password}")


def cmd_csv(api: MarcoAPI, args: argparse.Namespace) -> None:
    """Create users from a CSV file (columns: email, password)."""
    with open(args.file, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            email = row.get("email") or row.get("Email", "").strip()
            password = row.get("password") or row.get("Password") or random_password()
            if not email:
                continue
            try:
                api.create_user(email, password)
                print(f"  Created  {email}  password={password}")
            except MarcoError as e:
                print(f"  FAIL     {email}  {e}")
                if not args.keep_going:
                    sys.exit(1)


def cmd_generate(api: MarcoAPI, args: argparse.Namespace) -> None:
    """Generate N test users on a domain."""
    domain = args.domain
    password = args.password or random_password()
    count = args.count

    # Ensure domain exists.
    try:
        api.create_domain(domain)
    except MarcoError:
        pass  # already exists

    for i in range(1, count + 1):
        email = f"{random_username(i, args.prefix)}@{domain}"
        try:
            api.create_user(email, password)
            print(f"  [{i}/{count}] Created  {email}  password={password}")
        except MarcoError as e:
            print(f"  [{i}/{count}] FAIL      {email}  {e}")
            if not args.keep_going:
                sys.exit(1)


def cmd_manifest(api: MarcoAPI, args: argparse.Namespace) -> None:
    """Apply a JSON manifest (domains, users, aliases)."""
    with open(args.file) as f:
        manifest: dict[str, Any] = json.load(f)

    for domain in manifest.get("domains", []):
        name = domain if isinstance(domain, str) else domain["name"]
        try:
            api.create_domain(name)
            print(f"  Domain   {name}")
        except MarcoError as e:
            print(f"  Domain   {name}  {e}")
            if not args.keep_going:
                sys.exit(1)

    for user in manifest.get("users", []):
        email = user["email"]
        password = user.get("password", random_password())
        try:
            api.create_user(email, password)
            print(f"  User     {email}  password={password}")
        except MarcoError as e:
            print(f"  User     {email}  {e}")
            if not args.keep_going:
                sys.exit(1)

    for alias in manifest.get("aliases", []):
        try:
            api.create_alias(alias["source"], alias["destination"], alias["domain"])
            print(f"  Alias    {alias['source']} -> {alias['destination']}")
        except MarcoError as e:
            print(f"  Alias    {alias['source']}  {e}")
            if not args.keep_going:
                sys.exit(1)


def cmd_reset(api: MarcoAPI, args: argparse.Namespace) -> None:
    """Wipe users, domains, and aliases (optionally keep some emails)."""
    keep = set(args.keep or [])

    confirmed = input("This will delete ALL users, domains, and aliases.  Type 'yes' to confirm: ")
    if confirmed.strip().lower() != "yes":
        print("Aborted.")
        return

    for u in api.list_users():
        if u["email"] in keep:
            print(f"  Keeping  {u['email']}")
            continue
        api.delete_user(u["id"])
        print(f"  Deleted  user [{u['id']}] {u['email']}")

    # Domains referenced by remaining users can't be deleted, but attempt anyway.
    for d in api.list_domains():
        try:
            api.delete_domain(d)
            print(f"  Deleted  domain {d}")
        except MarcoError as e:
            print(f"  Keeping  domain {d}  ({e})")

    print("Reset complete.")


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Marco account management for testing")
    parser.add_argument("--url", default=None)
    parser.add_argument("--token", default=None)

    sub = parser.add_subparsers(dest="command", required=True)

    # single user
    p = sub.add_parser("one", help="Create a single user")
    p.add_argument("--email", required=True)
    p.add_argument("--password", default="")

    # CSV bulk import
    p = sub.add_parser("csv", help="Bulk create from CSV (columns: email, password)")
    p.add_argument("--file", "-f", required=True)
    p.add_argument("--keep-going", action="store_true", help="Don't stop on first error")

    # generate
    p = sub.add_parser("generate", help="Generate test users on a domain")
    p.add_argument("--count", type=int, required=True)
    p.add_argument("--domain", required=True)
    p.add_argument("--prefix", default="test")
    p.add_argument("--password", default="")
    p.add_argument("--keep-going", action="store_true")

    # manifest (JSON)
    p = sub.add_parser("manifest", help="Apply JSON manifest (domains, users, aliases)")
    p.add_argument("file")
    p.add_argument("--keep-going", action="store_true")

    # reset
    p = sub.add_parser("reset", help="Delete all users, domains, aliases")
    p.add_argument("--keep", nargs="*", default=[], help="Emails to keep")

    args = parser.parse_args()

    api = MarcoAPI(base_url=args.url).with_session()

    try:
        if args.command == "one":
            cmd_one(api, args)
        elif args.command == "csv":
            cmd_csv(api, args)
        elif args.command == "generate":
            cmd_generate(api, args)
        elif args.command == "manifest":
            cmd_manifest(api, args)
        elif args.command == "reset":
            cmd_reset(api, args)
    except MarcoError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
