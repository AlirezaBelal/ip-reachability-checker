# IP Reachability Checker

[![CI](https://github.com/AlirezaBelal/IPReachabilityChecker/actions/workflows/ci.yml/badge.svg)](https://github.com/AlirezaBelal/IPReachabilityChecker/actions/workflows/ci.yml)

A small, dependency-free Python CLI for checking **explicit IPv4/IPv6 targets** with either the operating system's ICMP `ping` command or a single TCP port.

The project is intentionally bounded: it validates literal IP addresses, does not expand CIDR ranges, does not scan multiple ports, and never invokes a shell.

## Product / operational context

The operational question this tool answers is deliberately narrow:

**Given a known list of infrastructure endpoints, which targets are reachable right now through ICMP or one expected TCP service port?**

The design favors predictable diagnostics over broad discovery. Operators get validated input, bounded concurrency, machine-readable output, explicit status semantics, and stable exit codes without turning the utility into a network scanner.

The intended outcomes are:

**fast triage · deterministic automation · cross-platform behavior · low operational risk**

## Highlights

- Cross-platform ICMP command construction for Windows, Linux, and macOS.
- Optional TCP reachability check for one explicit port.
- Strict IPv4/IPv6 validation with Python's standard-library `ipaddress` module.
- Batch input from command line or a text file, with deduplication and a 256-target cap.
- Bounded concurrency (`--workers`, maximum 32).
- Human-readable and JSON output.
- Automation-friendly exit codes.
- No third-party runtime dependencies.
- Unit tests plus real localhost TCP and cross-platform ICMP smoke tests in CI.

## Requirements

- Python 3.10+
- For ICMP mode: an OS `ping` utility available on `PATH`

TCP mode uses only Python's standard library and does not require `ping`.

## Usage

### ICMP ping

```bash
python ip_reachability_checker.py 127.0.0.1 ::1
```

Tune the packet count and timeout:

```bash
python ip_reachability_checker.py 192.0.2.10 --count 3 --timeout 1.5
```

`192.0.2.0/24` is reserved for documentation; examples do not rely on a public third-party host.

### TCP reachability

Check one explicit TCP port across the supplied IPs:

```bash
python ip_reachability_checker.py 127.0.0.1 --tcp-port 8000
```

This is a connection check, not a port scanner: the CLI accepts only one `--tcp-port` value per run and only explicit target IPs.

### Read targets from a file

```bash
python ip_reachability_checker.py --file targets.example.txt
```

The file format is one IP per line. Blank lines and lines beginning with `#` are ignored. CLI targets and file targets can be combined and are deduplicated.

### JSON output

```bash
python ip_reachability_checker.py 127.0.0.1 --tcp-port 8000 --json
```

Example shape:

```json
{
  "results": [
    {
      "detail": "port 8000",
      "ip": "127.0.0.1",
      "latency_ms": 0.42,
      "method": "tcp",
      "status": "reachable"
    }
  ],
  "summary": {
    "error": 0,
    "reachable": 1,
    "total": 1,
    "unreachable": 0
  }
}
```

## Status semantics

- `reachable` — the OS ping command returned success, or the TCP connection completed.
- `unreachable` — the ping attempt timed out/returned a normal non-success result, or the TCP connection could not be established within the configured timeout.
- `error` — the reachability check itself could not run, for example because the local `ping` executable is missing.

The tool deliberately does **not** claim to distinguish "filtered" from "unreachable". ICMP may be blocked even when a host is otherwise reachable, and TCP results are specific to the selected port.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | All targets were reachable |
| `1` | At least one target was unreachable |
| `2` | Invalid configuration/input or an operational check error occurred |

## Safety boundaries

This repository is designed for explicit, bounded connectivity checks:

- literal IPv4/IPv6 targets only;
- no hostname resolution;
- no CIDR/range expansion;
- maximum 256 unique targets;
- maximum 32 concurrent workers;
- one TCP port per run;
- `subprocess.run()` receives an argument list with `shell=False` behavior;
- raw ping output is not parsed or persisted.

Use network diagnostics only on systems and networks where you are authorized to do so.

## Testing

Run all tests:

```bash
python -m unittest discover -s tests -v
```

The test suite covers validation, deduplication, option limits, Windows/Linux/macOS ping command construction, ICMP process outcomes, JSON/exit-code semantics, and a real TCP connection against a temporary listener bound only to `127.0.0.1`.

GitHub Actions also runs a real localhost ICMP smoke check on Ubuntu, Windows, and macOS. CI never probes an external target.

## Project scope

This is a lightweight network-diagnostics CLI, not a network scanner, monitoring platform, traceroute implementation, packet sniffer, or service-discovery framework.

## License

MIT License. See `LICENSE`.
