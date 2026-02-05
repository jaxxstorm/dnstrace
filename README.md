# dnstrace

`dnstrace` performs a resolver-ladder trace by default (system resolvers first, then a small set of public resolvers for upstream comparison) and can run an authoritative delegation trace (similar to `dig +trace`) when requested. It explains *why* resolution succeeds or fails.

## Install

Build a static binary with Go:

```bash
go build ./cmd/dnstrace
```

## Usage

```bash
./dnstrace api.example.com A
./dnstrace api.example.com A --resolver 1.1.1.1 --resolver 8.8.8.8
./dnstrace trace api.example.com A
```

Common flags:

- `--output json` for machine-readable output
- `--transport tcp|udp|auto` to control transport
- `--max-time 2s` per-resolver time budget (ladder) or per-hop (authoritative)
- `--resolver <ip>` to provide a resolver list (repeatable)
- `trace` subcommand for authoritative delegation tracing
- `trace --verbose` to show per-nameserver responses in authoritative mode
- `--verbose` or `--debug` for logging (debug includes raw DNS messages)

## Example (Pretty)

```
01 100.100.100.100:53 api.example.com. A -> NOERROR rtt=15ms answers=api.example.com. 60 IN A 203.0.113.10
02 1.1.1.1:53 api.example.com. A -> NOERROR rtt=12ms answers=api.example.com. 60 IN A 203.0.113.10
SUCCESS resolver returned answer
```

## Example (JSON)

```bash
./dnstrace api.example.com A --output json
```

The JSON output includes:
- `trace_steps`: ordered list of queries/responses
- `diagnosis`: classification and explanation
- `timings`: RTT and timeout details
