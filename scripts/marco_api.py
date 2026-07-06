"""
Marco Admin API client — shared by all scripts in this directory.

Usage:
    from marco_api import MarcoAPI

    api = MarcoAPI(base_url="http://localhost:8080")
    api.login("admin@example.com", "secret123")
    users = api.list_users()
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


class MarcoError(Exception):
    """Raised on API errors or connection failures."""


class MarcoAPI:
    def __init__(self, base_url: Optional[str] = None, token: Optional[str] = None):
        self.base_url = (base_url or os.environ.get("MARCO_API_URL", "http://localhost:8080")).rstrip("/")
        self.token = token or os.environ.get("MARCO_API_TOKEN", "")
        self._session_path: Optional[Path] = None

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def login(self, email: str, password: str) -> str:
        """Authenticate and store the session token."""
        data = self._request("POST", "/api/login", {"email": email, "password": password})
        self.token = data["token"]
        return self.token

    def logout(self) -> None:
        self._request("POST", "/api/logout")
        self.token = ""

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def list_users(self) -> list[dict[str, Any]]:
        return self._request("GET", "/api/users") or []

    def create_user(self, email: str, password: str) -> dict[str, Any]:
        return self._request("POST", "/api/users", {"email": email, "password": password})

    def update_user(
        self,
        user_id: int,
        email: Optional[str] = None,
        password: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if email is not None:
            body["email"] = email
        if password is not None:
            body["password"] = password
        if is_active is not None:
            body["is_active"] = is_active
        return self._request("PUT", f"/api/users/{user_id}", body)

    def delete_user(self, user_id: int) -> dict[str, Any]:
        return self._request("DELETE", f"/api/users/{user_id}")

    # ------------------------------------------------------------------
    # Domains
    # ------------------------------------------------------------------

    def list_domains(self) -> list[str]:
        return self._request("GET", "/api/domains") or []

    def create_domain(self, name: str) -> dict[str, Any]:
        return self._request("POST", "/api/domains", {"name": name})

    def delete_domain(self, name: str) -> dict[str, Any]:
        return self._request("DELETE", f"/api/domains/{name}")

    # ------------------------------------------------------------------
    # Aliases
    # ------------------------------------------------------------------

    def list_aliases(self) -> list[dict[str, Any]]:
        return self._request("GET", "/api/aliases") or []

    def create_alias(self, source: str, destination: str, domain: str) -> dict[str, Any]:
        return self._request(
            "POST",
            "/api/aliases",
            {"source": source, "destination": destination, "domain": domain},
        )

    def delete_alias(self, alias_id: int) -> dict[str, Any]:
        return self._request("DELETE", f"/api/aliases/{alias_id}")

    # ------------------------------------------------------------------
    # Queue
    # ------------------------------------------------------------------

    def list_queue(self) -> list[dict[str, Any]]:
        return self._request("GET", "/api/queue") or []

    def delete_queue_item(self, item_id: int) -> dict[str, Any]:
        return self._request("DELETE", f"/api/queue/{item_id}")

    # ------------------------------------------------------------------
    # Stats & health
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        return self._request("GET", "/api/stats")

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/api/health", auth=False)

    def metrics(self) -> str:
        """Return raw Prometheus text from the metrics endpoint."""
        return self._request("GET", "/api/metrics", auth=False, raw=True)

    # ------------------------------------------------------------------
    # DKIM
    # ------------------------------------------------------------------

    def rotate_dkim(self) -> dict[str, Any]:
        return self._request("POST", "/api/dkim/rotate")

    # ------------------------------------------------------------------
    # Session persistence
    # ------------------------------------------------------------------

    def save_session(self, path: Optional[Path] = None) -> Path:
        """Save token to disk so other scripts can reuse it."""
        p = path or Path(os.environ.get("MARCO_SESSION", "~/.marco_token")).expanduser()
        p.write_text(self.token)
        self._session_path = p
        p.chmod(0o600)
        return p

    def load_session(self, path: Optional[Path] = None) -> str:
        """Load a previously-saved token."""
        p = path or Path(os.environ.get("MARCO_SESSION", "~/.marco_token")).expanduser()
        if p.exists():
            self.token = p.read_text().strip()
            self._session_path = p
        return self.token

    def with_session(self) -> "MarcoAPI":
        """Convenience: load saved session or prompt login, then save."""
        if not self.token:
            self.load_session()
        if not self.token:
            url = os.environ.get("MARCO_API_URL", self.base_url)
            print(f"Authenticating against {url} ...", file=sys.stderr)
            email = os.environ.get("MARCO_ADMIN_EMAIL", "")
            password = os.environ.get("MARCO_ADMIN_PASSWORD", "")
            if not email:
                email = input("Admin email: ").strip()
            if not password:
                password = input("Password: ").strip()
            self.login(email, password)
            self.save_session()
        return self

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[dict] = None,
        auth: bool = True,
        raw: bool = False,
    ) -> Any:
        url = f"{self.base_url}{path}"
        headers = {"Content-Type": "application/json"}
        if auth and self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        data = json.dumps(body).encode() if body is not None else None
        req = Request(url, data=data, headers=headers, method=method)

        try:
            with urlopen(req, timeout=30) as resp:
                content = resp.read()
        except HTTPError as e:
            msg = self._extract_error(e)
            raise MarcoError(f"{e.code} {e.reason}: {msg}") from e
        except URLError as e:
            raise MarcoError(f"Connection failed: {e.reason}") from e
        except OSError as e:
            raise MarcoError(str(e)) from e

        if raw:
            return content.decode()

        return json.loads(content).get("data")

    @staticmethod
    def _extract_error(err: HTTPError) -> str:
        try:
            body = json.loads(err.read())
            return body.get("error", err.reason or "")
        except Exception:
            return err.reason or str(err)


# ------------------------------------------------------------------
# CLI entry point for quick one-liners
# ------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Marco Admin API client")
    parser.add_argument("--url", default=os.environ.get("MARCO_API_URL", "http://localhost:8080"))
    parser.add_argument("--token", default=os.environ.get("MARCO_API_TOKEN", ""))
    sub = parser.add_subparsers(dest="command", required=True)

    # login
    p = sub.add_parser("login")
    p.add_argument("email")
    p.add_argument("password")

    # list users
    sub.add_parser("list-users")

    # create user
    p = sub.add_parser("create-user")
    p.add_argument("email")
    p.add_argument("password")

    # delete user
    p = sub.add_parser("delete-user")
    p.add_argument("id", type=int)

    # list domains
    sub.add_parser("list-domains")

    # create domain
    p = sub.add_parser("create-domain")
    p.add_argument("name")

    # delete domain
    p = sub.add_parser("delete-domain")
    p.add_argument("name")

    # list aliases
    sub.add_parser("list-aliases")

    # create alias
    p = sub.add_parser("create-alias")
    p.add_argument("source")
    p.add_argument("destination")
    p.add_argument("domain")

    # delete alias
    p = sub.add_parser("delete-alias")
    p.add_argument("id", type=int)

    # queue
    sub.add_parser("list-queue")

    # delete queue item
    p = sub.add_parser("delete-queue")
    p.add_argument("id", type=int)

    # stats
    sub.add_parser("stats")

    # health
    sub.add_parser("health")

    # rotate dkim
    sub.add_parser("rotate-dkim")

    args = parser.parse_args()

    api = MarcoAPI(base_url=args.url, token=args.token)

    try:
        if args.command == "login":
            t = api.login(args.email, args.password)
            api.save_session()
            print(f"Token saved.  ({len(t)} chars)")
        elif args.command == "list-users":
            api.with_session()
            for u in api.list_users():
                print(f"  [{u['id']}] {u['email']}  active={u.get('is_active', '?')}")
        elif args.command == "create-user":
            api.with_session()
            api.create_user(args.email, args.password)
            print(f"Created user {args.email}")
        elif args.command == "delete-user":
            api.with_session()
            api.delete_user(args.id)
            print(f"Deleted user {args.id}")
        elif args.command == "list-domains":
            api.with_session()
            for d in api.list_domains():
                print(f"  {d}")
        elif args.command == "create-domain":
            api.with_session()
            api.create_domain(args.name)
            print(f"Created domain {args.name}")
        elif args.command == "delete-domain":
            api.with_session()
            api.delete_domain(args.name)
            print(f"Deleted domain {args.name}")
        elif args.command == "list-aliases":
            api.with_session()
            for a in api.list_aliases():
                print(f"  [{a['id']}] {a['source']} -> {a['destination']} @ {a.get('domain', '?')}")
        elif args.command == "create-alias":
            api.with_session()
            r = api.create_alias(args.source, args.destination, args.domain)
            print(f"Created alias id={r.get('id', '?')}")
        elif args.command == "delete-alias":
            api.with_session()
            api.delete_alias(args.id)
            print(f"Deleted alias {args.id}")
        elif args.command == "list-queue":
            api.with_session()
            items = api.list_queue()
            if not items:
                print("Queue empty")
            for q in items:
                print(f"  [{q['id']}] to={q.get('rcpt_to', '?')}  attempts={q.get('attempt_count', 0)}")
        elif args.command == "delete-queue":
            api.with_session()
            api.delete_queue_item(args.id)
            print(f"Deleted queue item {args.id}")
        elif args.command == "stats":
            api.with_session()
            s = api.stats()
            for k, v in s.items():
                print(f"  {k}: {v}")
        elif args.command == "health":
            h = api.health()
            print(h)
        elif args.command == "rotate-dkim":
            api.with_session()
            r = api.rotate_dkim()
            print("DKIM key rotated.")
            print(f"  Selector:  {r['selector']}")
            print(f"  Domain:    {r['domain']}")
            print(f"  DNS TXT:   {r['dns_record']}")
    except MarcoError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
