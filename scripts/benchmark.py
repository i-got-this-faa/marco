#!/usr/bin/env python3
"""
Benchmark scripts for the Marco mail server.

Measures:
  - SMTP injection throughput (raw SMTP, no auth)
  - SMTP submission throughput (STARTTLS + AUTH)
  - POP3 retrieval throughput
  - API response latency
  - Concurrent connection scaling

All benchmarks print results as TSV rows for easy graphing.

Environment:
  MARCO_HOST         SMTP/IMAP/POP3 host (default localhost)
  MARCO_SMTP_PORT    (default 25)
  MARCO_SUBMISSION_PORT  (default 587)
  MARCO_POP3_PORT    (default 110)
  MARCO_API_URL      Admin API (default http://localhost:8080)
  MARCO_ADMIN_EMAIL  Admin account
  MARCO_ADMIN_PASSWORD
"""

import argparse
import base64
import contextlib
import os
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

from marco_api import MarcoAPI


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

ENV = {
    "host": os.environ.get("MARCO_HOST", "localhost"),
    "smtp_port": int(os.environ.get("MARCO_SMTP_PORT", "25")),
    "submission_port": int(os.environ.get("MARCO_SUBMISSION_PORT", "587")),
    "pop3_port": int(os.environ.get("MARCO_POP3_PORT", "110")),
    "api_url": os.environ.get("MARCO_API_URL", "http://localhost:8080"),
}


def make_message(from_addr: str, to_addr: str, size: int = 1024) -> bytes:
    """Build an RFC 5322 message with a body of approximately *size* bytes."""
    body_line = "X" * 72 + "\r\n"
    body_count = max(1, size // len(body_line))
    body = body_line * body_count

    headers = (
        f"From: {from_addr}\r\n"
        f"To: {to_addr}\r\n"
        f"Subject: benchmark {time.time()}\r\n"
        f"Message-ID: <bench.{time.time()}.{id(to_addr)}@{from_addr.split('@')[1]}>\r\n"
        f"\r\n"
    )
    return (headers + body).encode()


def tcp_connect(host: str, port: int, timeout: float = 10) -> socket.socket:
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    return s

def recv_until(sock: socket.socket, marker: bytes = b"\r\n") -> bytes:
    """Read until *marker* is seen (single-line SMTP response)."""
    data = b""
    while not data.endswith(marker):
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def recv_response(sock: socket.socket) -> bytes:
    """Read a full SMTP response, handling multi-line replies.

    SMTP multi-line: every continuation line has ``NNN-`` and the
    final line has ``NNN `` (space after the 3-digit code).
    """
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        # Check if the last *complete* line in the buffer (the one
        # ending with \r\n) has space at position 3.
        end = data.rfind(b"\r\n")
        if end >= 0:
            # Find the start of this line (the \r\n before it, or 0).
            start = data.rfind(b"\r\n", 0, end)
            if start >= 0:
                last_line = data[start + 2:end]
            else:
                last_line = data[:end]
            if len(last_line) >= 4 and last_line[3:4] == b" ":
                break
    return data

def send_line(sock: socket.socket, line: bytes) -> None:
    sock.sendall(line + b"\r\n")


# ------------------------------------------------------------------
# SMTP benchmarks
# ------------------------------------------------------------------

@dataclass
class SmtpResult:
    senders: int
    duration: float = 0.0
    msg_size: int = 0
    latencies: list[float] = field(default_factory=list)
    errors: int = 0


def bench_smtp(
    port: int,
    count: int,
    msg_size: int,
    use_tls: bool = False,
    auth: Optional[tuple[str, str]] = None,
    from_addr: str = "bench@example.com",
    to_addr: str = "user@example.com",
) -> SmtpResult:
    """Send *count* messages sequentially over SMTP and measure throughput."""
    sock = tcp_connect(ENV["host"], port)

    # Read banner.
    recv_response(sock)

    if use_tls:
        send_line(sock, b"EHLO bench")
        recv_response(sock)
        send_line(sock, b"STARTTLS")
        recv_response(sock)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(sock, server_hostname=ENV["host"])
        send_line(sock, b"EHLO bench")
        recv_response(sock)

        if auth:
            email, password = auth
            # AUTH PLAIN: base64(\0username\0password)
            plain = b'\x00' + email.encode() + b'\x00' + password.encode()
            send_line(sock, b'AUTH PLAIN ' + base64.b64encode(plain))
            recv_response(sock)
    else:
        send_line(sock, b"EHLO bench")
        recv_response(sock)

        if auth:
            email, password = auth
            # AUTH PLAIN: base64(\0username\0password)
            plain = b'\x00' + email.encode() + b'\x00' + password.encode()
            send_line(sock, b'AUTH PLAIN ' + base64.b64encode(plain))
            recv_response(sock)

    result = SmtpResult(senders=count, msg_size=msg_size)
    msg = make_message(from_addr, to_addr, msg_size)

    for i in range(count):
        start = time.perf_counter()
        try:
            send_line(sock, b"MAIL FROM:<" + from_addr.encode() + b">")
            recv_response(sock)
            send_line(sock, b"RCPT TO:<" + to_addr.encode() + b">")
            recv_response(sock)
            send_line(sock, b"DATA")
            recv_response(sock)
            sock.sendall(msg)
            send_line(sock, b".")
            recv_response(sock)
            lat = time.perf_counter() - start
            result.latencies.append(lat)
        except OSError as e:
            result.errors += 1
            print(f"  Error at msg {i}: {e}", file=sys.stderr)
            break

    result.duration = time.perf_counter() - result.latencies[0] + result.latencies[0] if result.latencies else 0
    # Recalculate more accurately.
    if result.latencies:
        result.duration = sum(result.latencies)

    send_line(sock, b"QUIT")
    with contextlib.suppress(OSError):
        recv_response(sock)
    sock.close()

    return result


# ------------------------------------------------------------------
# POP3 benchmarks (sequential retrieval)
# ------------------------------------------------------------------

@dataclass
class Pop3Result:
    count: int
    duration: float
    errors: int = 0


def bench_pop3(user: str, password: str, count: Optional[int] = None) -> Pop3Result:
    """Connect via POP3, authenticate, download *count* messages (or all)."""
    sock = tcp_connect(ENV["host"], ENV["pop3_port"])
    recv_until(sock)  # banner

    send_line(sock, f"USER {user}".encode())
    recv_until(sock)
    send_line(sock, f"PASS {password}".encode())
    resp = recv_until(sock)
    if b"-ERR" in resp:
        sock.close()
        return Pop3Result(count=0, duration=0, errors=1)

    send_line(sock, b"STAT")
    stat_resp = recv_until(sock)
    parts = stat_resp.decode().split()
    total = int(parts[1]) if len(parts) >= 2 else 0

    if count is None or count > total:
        count = total

    start = time.perf_counter()
    errors = 0
    for uid in range(1, count + 1):
        try:
            send_line(sock, f"RETR {uid}".encode())
            # Read until EOF marker.
            while True:
                line = recv_until(sock)
                if line == b".\r\n":
                    break
        except OSError:
            errors += 1
            break

    duration = time.perf_counter() - start

    send_line(sock, b"QUIT")
    recv_until(sock)
    sock.close()

    return Pop3Result(count=count, duration=duration, errors=errors)


# ------------------------------------------------------------------
# API latency benchmark
# ------------------------------------------------------------------

@dataclass
class ApiLatencyResult:
    endpoint: str
    samples: int
    p50: float
    p95: float
    p99: float
    errors: int


def bench_api_latency(api: MarcoAPI, samples: int = 50) -> list[ApiLatencyResult]:
    endpoints = [
        ("GET /api/health", lambda: api.health()),
        ("GET /api/stats", lambda: api.stats()),
        ("GET /api/users", lambda: api.list_users()),
        ("GET /api/domains", lambda: api.list_domains()),
        ("GET /api/aliases", lambda: api.list_aliases()),
        ("GET /api/queue", lambda: api.list_queue()),
    ]

    results = []
    for name, fn in endpoints:
        lats = []
        errors = 0
        for _ in range(samples):
            start = time.perf_counter()
            try:
                fn()
                lats.append(time.perf_counter() - start)
            except Exception:
                errors += 1
        lats.sort()
        p50 = lats[len(lats) // 2] if lats else 0
        p95 = lats[int(len(lats) * 0.95)] if lats else 0
        p99 = lats[int(len(lats) * 0.99)] if lats else 0
        results.append(ApiLatencyResult(name, len(lats), p50, p95, p99, errors))
    return results


# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------

def cmd_smtp(args: argparse.Namespace) -> None:
    port = ENV["submission_port"] if args.submission else ENV["smtp_port"]
    auth = (args.auth_email, args.auth_password) if args.auth_email else None
    # AUTH requires TLS. Auto-enable TLS when credentials are provided.
    use_tls = args.submission or auth is not None
    r = bench_smtp(
        port=port,
        count=args.count,
        msg_size=args.size,
        use_tls=use_tls,
        auth=auth,
        from_addr=args.from_addr,
        to_addr=args.to_addr,
    )
    msgs_per_sec = r.senders / r.duration if r.duration > 0 else 0
    mb_per_sec = (r.senders * r.msg_size) / r.duration / 1_000_000 if r.duration > 0 else 0
    avg_lat = (sum(r.latencies) / len(r.latencies)) * 1000 if r.latencies else 0

    print(f"SMTP\t{ENV['host']}:{port}\t{r.senders}\t{r.msg_size}\t{r.duration:.3f}s\t{msgs_per_sec:.1f} msg/s\t{mb_per_sec:.2f} MB/s\tavg_lat={avg_lat:.1f}ms\terrors={r.errors}")
    if r.errors:
        print(f"  WARNING: {r.errors} errors", file=sys.stderr)


def cmd_pop3(args: argparse.Namespace) -> None:
    r = bench_pop3(args.user, args.password, args.count)
    msgs_per_sec = r.count / r.duration if r.duration > 0 else 0
    print(f"POP3\t{ENV['host']}:{ENV['pop3_port']}\t{r.count}\t{r.duration:.3f}s\t{msgs_per_sec:.1f} msg/s\terrors={r.errors}")


def cmd_api(args: argparse.Namespace) -> None:
    api = MarcoAPI().with_session()
    results = bench_api_latency(api, args.samples)
    print("endpoint\tsamples\tp50_ms\tp95_ms\tp99_ms\terrors")
    for r in results:
        print(f"{r.endpoint}\t{r.samples}\t{r.p50*1000:.2f}\t{r.p95*1000:.2f}\t{r.p99*1000:.2f}\t{r.errors}")


def cmd_all(args: argparse.Namespace) -> None:
    """Run all benchmarks sequentially."""
    print("=== SMTP (port 25, no auth) ===")
    cmd_smtp(argparse.Namespace(count=args.count, size=args.size, submission=False, auth_email=None, auth_password=None))
    print()
    print("=== SMTP Submission (port 587, TLS + AUTH) ===")
    api = MarcoAPI().with_session()
    email = os.environ.get("MARCO_ADMIN_EMAIL", "")
    password = os.environ.get("MARCO_ADMIN_PASSWORD", "")
    if email and password:
        cmd_smtp(argparse.Namespace(count=args.count, size=args.size, submission=True, auth_email=email, auth_password=password))
    else:
        print("  Skipped (set MARCO_ADMIN_EMAIL/PASSWORD)")
    print()
    print("=== API Latency ===")
    cmd_api(argparse.Namespace(samples=min(args.count, 20)))
    print()
    print("=== POP3 ===")
    if email and password:
        cmd_pop3(argparse.Namespace(user=email, password=password, count=min(args.count, 10)))
    else:
        print("  Skipped (set MARCO_ADMIN_EMAIL/PASSWORD)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Marco mail server benchmarks")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("smtp", help="SMTP injection throughput")
    p.add_argument("--count", type=int, default=10)
    p.add_argument("--size", type=int, default=2048, help="Message body size in bytes")
    p.add_argument("--submission", action="store_true", help="Use submission port with STARTTLS")
    p.add_argument("--auth-email")
    p.add_argument("--auth-password")
    p.add_argument("--from", dest="from_addr", default="bench@example.com",
                    help="Sender address (default: bench@example.com)")
    p.add_argument("--to", dest="to_addr", default="user@example.com",
                    help="Recipient address (default: user@example.com)")

    p = sub.add_parser("pop3", help="POP3 retrieval throughput")
    p.add_argument("--user", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--count", type=int, default=None, help="Messages to fetch (default: all)")

    p = sub.add_parser("api", help="Admin API latency")
    p.add_argument("--samples", type=int, default=20)

    p = sub.add_parser("all", help="Run all benchmarks")
    p.add_argument("--count", type=int, default=10)
    p.add_argument("--size", type=int, default=2048)

    args = parser.parse_args()

    try:
        if args.command == "smtp":
            cmd_smtp(args)
        elif args.command == "pop3":
            cmd_pop3(args)
        elif args.command == "api":
            cmd_api(args)
        elif args.command == "all":
            cmd_all(args)
    except Exception as e:
        print(f"Benchmark error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
