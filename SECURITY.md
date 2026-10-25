# Security Policy

## Scope

IP Reachability Checker performs bounded network diagnostics against explicit IP addresses supplied by the operator. It does not expand CIDR blocks, resolve hostnames, enumerate ports, or persist raw network command output.

## Safety properties

- Targets are parsed with Python's `ipaddress.ip_address()` before use.
- ICMP commands are executed as argument arrays; user input is never passed through a shell.
- TCP mode accepts one port per run and validates it to `1..65535`.
- Batch size is capped at 256 unique IPs and concurrency at 32 workers. File input is also bounded to 4,096 physical lines and 512 characters per line, preventing unbounded duplicate-only input and excessively long reads.
- Timeouts and ICMP packet counts are bounded.
- CI integration traffic is restricted to loopback (`127.0.0.1`) across Ubuntu, Windows and macOS.
- There are no runtime credentials, tokens, cookies, or API keys.

## Operational considerations

A failed ICMP ping does not prove that a host is offline; firewalls and host policies may suppress ICMP. TCP reachability describes only the selected port. Results should be treated as diagnostic signals rather than authoritative host-health data.

## Reporting

If you find a vulnerability, avoid including secrets or sensitive network data in a public issue. Report enough detail to reproduce the problem safely.
