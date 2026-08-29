#!/usr/bin/env python3
"""Bounded IP reachability checks using OS ping or one TCP port."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
import errno
import ipaddress
import json
import math
from pathlib import Path
import platform
import socket
import subprocess
import sys
import time
from typing import Callable, Iterable, Sequence

MAX_TARGETS = 256
MAX_WORKERS = 32
MAX_PING_COUNT = 10

_NETWORK_FAILURE_ERRNOS = {
    value
    for name in (
        "ECONNREFUSED",
        "ECONNRESET",
        "ETIMEDOUT",
        "EHOSTUNREACH",
        "ENETUNREACH",
        "EHOSTDOWN",
        "ENETDOWN",
    )
    if (value := getattr(errno, name, None)) is not None
}
_WINDOWS_NETWORK_FAILURES = {
    10050,  # WSAENETDOWN
    10051,  # WSAENETUNREACH
    10054,  # WSAECONNRESET
    10060,  # WSAETIMEDOUT
    10061,  # WSAECONNREFUSED
    10064,  # WSAEHOSTDOWN
    10065,  # WSAEHOSTUNREACH
}


class ConfigurationError(ValueError):
    """Raised when CLI or target input is invalid."""


@dataclass(frozen=True)
class ReachabilityResult:
    ip: str
    method: str
    status: str
    latency_ms: float | None = None
    detail: str = ""

    @property
    def reachable(self) -> bool:
        return self.status == "reachable"


def normalize_ip(value: str) -> str:
    """Validate one explicit IPv4/IPv6 address and return its canonical form."""
    raw = str(value or "").strip()
    if not raw:
        raise ConfigurationError("IP address is empty")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError as exc:
        raise ConfigurationError("invalid IP address") from exc


def _iter_file_targets(path: Path) -> Iterable[str]:
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            for line in handle:
                value = line.strip()
                if not value or value.startswith("#"):
                    continue
                yield value
    except FileNotFoundError as exc:
        raise ConfigurationError("target file was not found") from exc
    except OSError as exc:
        raise ConfigurationError("target file could not be read") from exc


def collect_targets(values: Sequence[str], file_path: Path | None = None) -> list[str]:
    """Validate, deduplicate, and bound explicit target IPs."""
    raw_targets = list(values)
    if file_path is not None:
        raw_targets.extend(_iter_file_targets(file_path))
    if not raw_targets:
        raise ConfigurationError("provide at least one IP address or --file")

    targets: list[str] = []
    seen: set[str] = set()
    for raw in raw_targets:
        target = normalize_ip(raw)
        if target in seen:
            continue
        seen.add(target)
        targets.append(target)
        if len(targets) > MAX_TARGETS:
            raise ConfigurationError(f"at most {MAX_TARGETS} unique IP addresses are allowed")
    return targets


def build_ping_command(
    ip: str,
    count: int,
    timeout_seconds: float,
    system_name: str | None = None,
) -> list[str]:
    """Build a shell-free ping command for Windows, Linux, or macOS."""
    target = ipaddress.ip_address(normalize_ip(ip))
    system = (system_name or platform.system()).casefold()

    if system == "windows":
        family_flag = "-6" if target.version == 6 else "-4"
        return [
            "ping",
            family_flag,
            "-n",
            str(count),
            "-w",
            str(max(1, math.ceil(timeout_seconds * 1000))),
            str(target),
        ]
    if system == "linux":
        family_flag = "-6" if target.version == 6 else "-4"
        return [
            "ping",
            family_flag,
            "-c",
            str(count),
            "-W",
            str(max(1, math.ceil(timeout_seconds))),
            str(target),
        ]
    if system == "darwin":
        executable = "ping6" if target.version == 6 else "ping"
        command = [executable, "-c", str(count)]
        if target.version == 4:
            command.extend(["-W", str(max(1, math.ceil(timeout_seconds * 1000)))])
        command.append(str(target))
        return command
    raise ConfigurationError(f"unsupported operating system for ICMP ping: {system_name or platform.system()}")


def check_icmp(
    ip: str,
    count: int = 2,
    timeout_seconds: float = 1.0,
    *,
    runner=subprocess.run,
    system_name: str | None = None,
) -> ReachabilityResult:
    """Run the platform ping command and classify by process outcome, not localized text."""
    target = normalize_ip(ip)
    command = build_ping_command(target, count, timeout_seconds, system_name=system_name)
    deadline = max(2.0, count * timeout_seconds + 2.0)
    started = time.perf_counter()
    try:
        completed = runner(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=deadline,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ReachabilityResult(target, "icmp", "unreachable", detail="ping timed out")
    except FileNotFoundError:
        return ReachabilityResult(target, "icmp", "error", detail="ping executable was not found")
    except OSError:
        return ReachabilityResult(target, "icmp", "error", detail="ping process could not be started")

    latency_ms = round((time.perf_counter() - started) * 1000, 2)
    if completed.returncode == 0:
        return ReachabilityResult(target, "icmp", "reachable", latency_ms=latency_ms)
    if completed.returncode == 1:
        return ReachabilityResult(target, "icmp", "unreachable", latency_ms=latency_ms)
    return ReachabilityResult(target, "icmp", "error", latency_ms=latency_ms, detail="ping exited with an operational error")


def _is_network_failure(exc: OSError) -> bool:
    return exc.errno in _NETWORK_FAILURE_ERRNOS or getattr(exc, "winerror", None) in _WINDOWS_NETWORK_FAILURES


def check_tcp(
    ip: str,
    port: int,
    timeout_seconds: float = 1.0,
    *,
    connector: Callable[..., object] = socket.create_connection,
) -> ReachabilityResult:
    """Attempt one TCP connection to an explicit IP and one explicit port."""
    target = normalize_ip(ip)
    started = time.perf_counter()
    try:
        with connector((target, port), timeout=timeout_seconds):
            latency_ms = round((time.perf_counter() - started) * 1000, 2)
            return ReachabilityResult(target, "tcp", "reachable", latency_ms=latency_ms, detail=f"port {port}")
    except (ConnectionRefusedError, TimeoutError, socket.timeout):
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        return ReachabilityResult(target, "tcp", "unreachable", latency_ms=latency_ms, detail=f"port {port}")
    except OSError as exc:
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        if _is_network_failure(exc):
            return ReachabilityResult(target, "tcp", "unreachable", latency_ms=latency_ms, detail=f"port {port}")
        return ReachabilityResult(
            target,
            "tcp",
            "error",
            latency_ms=latency_ms,
            detail="TCP check failed locally",
        )


def check_targets(
    targets: Sequence[str],
    *,
    tcp_port: int | None,
    count: int,
    timeout_seconds: float,
    workers: int,
) -> list[ReachabilityResult]:
    """Check a bounded target set concurrently while preserving input order."""
    if tcp_port is None:
        check = lambda target: check_icmp(target, count=count, timeout_seconds=timeout_seconds)
    else:
        check = lambda target: check_tcp(target, port=tcp_port, timeout_seconds=timeout_seconds)

    with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as executor:
        return list(executor.map(check, targets))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check explicit IPv4/IPv6 targets with ICMP ping or one TCP port."
    )
    parser.add_argument("targets", nargs="*", help="Explicit IPv4 or IPv6 addresses")
    parser.add_argument("--file", type=Path, help="Text file containing one explicit IP per line")
    parser.add_argument("--tcp-port", type=int, help="Use a TCP connection check instead of ICMP ping")
    parser.add_argument("--count", type=int, default=2, help="ICMP packets per target (1-10; default: 2)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Per-attempt timeout in seconds (0.1-10; default: 1)")
    parser.add_argument("--workers", type=int, default=8, help="Concurrent targets (1-32; default: 8)")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    return parser


def validate_options(args: argparse.Namespace) -> None:
    if args.tcp_port is not None and not 1 <= args.tcp_port <= 65535:
        raise ConfigurationError("tcp_port must be between 1 and 65535")
    if not 1 <= args.count <= MAX_PING_COUNT:
        raise ConfigurationError(f"count must be between 1 and {MAX_PING_COUNT}")
    if not 0.1 <= args.timeout <= 10:
        raise ConfigurationError("timeout must be between 0.1 and 10 seconds")
    if not 1 <= args.workers <= MAX_WORKERS:
        raise ConfigurationError(f"workers must be between 1 and {MAX_WORKERS}")


def _summary(results: Sequence[ReachabilityResult]) -> dict[str, int]:
    return {
        "total": len(results),
        "reachable": sum(result.status == "reachable" for result in results),
        "unreachable": sum(result.status == "unreachable" for result in results),
        "error": sum(result.status == "error" for result in results),
    }


def render_json(results: Sequence[ReachabilityResult]) -> str:
    return json.dumps(
        {"results": [asdict(result) for result in results], "summary": _summary(results)},
        indent=2,
        sort_keys=True,
    )


def render_text(results: Sequence[ReachabilityResult]) -> str:
    lines: list[str] = []
    for result in results:
        latency = f" {result.latency_ms:.2f}ms" if result.latency_ms is not None else ""
        detail = f" ({result.detail})" if result.detail else ""
        lines.append(f"{result.ip:<39} {result.status:<11} {result.method}{latency}{detail}")
    summary = _summary(results)
    lines.append(
        f"Summary: total={summary['total']} reachable={summary['reachable']} "
        f"unreachable={summary['unreachable']} error={summary['error']}"
    )
    return "\n".join(lines)


def exit_code_for(results: Sequence[ReachabilityResult]) -> int:
    if any(result.status == "error" for result in results):
        return 2
    if any(result.status == "unreachable" for result in results):
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        validate_options(args)
        targets = collect_targets(args.targets, args.file)
        results = check_targets(
            targets,
            tcp_port=args.tcp_port,
            count=args.count,
            timeout_seconds=args.timeout,
            workers=args.workers,
        )
    except ConfigurationError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    print(render_json(results) if args.json else render_text(results))
    return exit_code_for(results)


if __name__ == "__main__":
    raise SystemExit(main())
