# IP Reachability Checker

[![CI](https://github.com/AlirezaBelal/ip-reachability-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/AlirezaBelal/ip-reachability-checker/actions/workflows/ci.yml)

A small, dependency-free Python CLI for checking **explicit IPv4/IPv6 targets** with either the operating system's ICMP `ping` command or a single TCP port.

The project is intentionally bounded: it validates literal IP addresses, does not expand CIDR ranges, does not scan multiple ports, and never invokes a shell.

## Highlights

- Cross-platform ICMP command construction for Windows, Linux, and macOS.
- Optional TCP reachability check for one explicit port.
- Strict IPv4/IPv6 validation with Python's standard-library `ipaddress` module.
- Batch input from command line or a streamed UTF-8 text file, with deduplication, a 256-target cap, and bounded file line/length processing.
- Bounded concurrency (`--workers`, maximum 32).
- Human-readable and JSON output.
- Automation-friendly exit codes, including clean `Ctrl+C` handling with exit code `130`.
- No third-party runtime dependencies.
- Unit tests plus real localhost TCP and cross-platform ICMP smoke tests in CI.

## Requirements

- Python 3.10+
- For ICMP mode: an OS `ping` utility available on `PATH`

TCP mode uses only Python's standard library and does not require `ping`.

## Quick start

Clone the repository; no package installation is needed:

```bash
git clone https://github.com/AlirezaBelal/ip-reachability-checker.git
cd ip-reachability-checker
python ip_reachability_checker.py 127.0.0.1 --count 1
```

## Usage

### ICMP ping

```bash
python ip_reachability_checker.py 127.0.0.1 ::1
```

Tune the packet count and timeout:

```bash
python ip_reachability_checker.py 127.0.0.1 --count 3 --timeout 1.5
```

All executable examples use loopback targets. TCP port 8000 must have a local listener for a reachable result.

### TCP reachability

Check one explicit TCP port across the supplied IPs:

```bash
python ip_reachability_checker.py 127.0.0.1 --tcp-port 8000
```

This is a connection check, not a port scanner: the CLI accepts only one `--tcp-port` value per run and only explicit target IPs.

### Read targets from a file

```bash
printf "127.0.0.1\n::1\n" > targets.txt
python ip_reachability_checker.py --file targets.txt
```

The file format is one IP per line. Blank lines and lines beginning with `#` are ignored, **but count toward the 4,096-line file limit**. Each line is limited to **512 characters**, excluding its line ending; long lines are rejected using bounded reads. UTF-8 BOM is accepted. CLI targets and file targets can be combined and are deduplicated. Invalid targets fail fast instead of being silently skipped, which keeps automation inputs deterministic.

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

## Timing and limits

| Option | Default | Allowed |
| --- | --- | --- |
| `--count` | 2 | 1–10 ICMP packets |
| `--timeout` | 1 | 0.1–10 seconds, finite |
| `--workers` | 8 | 1–32 concurrent targets |
| `--tcp-port` | ICMP mode | One port, 1–65535 |

Target files: at most **4,096 physical lines** of **512 characters** each, including comments and blank lines. This is separate from the **256 unique IPs** limit.

`--timeout` is the TCP connection timeout. ICMP uses OS-specific response waits:
Linux rounds up to whole seconds; Windows and macOS IPv4 use milliseconds.
macOS `ping6` has no equivalent response-wait option, so only the overall process
deadline is enforced there. Each ping process is capped at
`count * (ceil(timeout) + 1) + 2` seconds, allowing default packet spacing and startup.

The historical JSON key `latency_ms` is retained for compatibility. It measures
**overall check duration**, including process startup and packet spacing for ICMP;
it is not packet RTT. Text output labels it `duration`. Example values are illustrative.

`Ctrl+C` returns 130 after active bounded checks finish; it does not immediately
cancel running threads. Target files are processed incrementally with bounded
line lengths and line counts, even for duplicate-only or comment-only input.
Very large command-line argument lists remain subject to OS/terminal limits.

## Status semantics

- `reachable` — the OS ping command returned success, or the TCP connection completed.
- `unreachable` — the ping attempt timed out/returned a normal non-success result, or the TCP connection could not be established within the configured timeout.
- `error` — the reachability check itself could not run, for example because the local `ping` executable is missing or a local socket resource error occurs.

The tool deliberately does **not** claim to distinguish "filtered" from "unreachable". ICMP may be blocked even when a host is otherwise reachable, and TCP results are specific to the selected port.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | All targets were reachable |
| `1` | At least one target was unreachable |
| `2` | Invalid configuration/input or an operational check error occurred |
| `130` | Execution was interrupted by the operator (`Ctrl+C`) |

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

The test suite covers validation, streamed target-file handling, deduplication, option limits, Windows/Linux/macOS ping command construction, ICMP/TCP result classification, JSON/exit-code semantics, clean interruption behavior, and a real TCP connection against a temporary listener bound only to `127.0.0.1`.

GitHub Actions also runs the full portable test suite (including real localhost TCP) and a real localhost ICMP smoke check on **Ubuntu, Windows and macOS**, plus the Python 3.10–3.14 version matrix. CI never probes an external target.

## Project scope

This is a lightweight network-diagnostics CLI, not a network scanner, monitoring platform, traceroute implementation, packet sniffer, or service-discovery framework.

## License

MIT License. See `LICENSE`.
