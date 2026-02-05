## Context

We are introducing a new CLI tool, `dnstrace`, to provide evidence-based DNS tracing and diagnostics. The core mode is a resolver-ladder trace (system resolvers by default, configurable via flags), and the tool can also perform authoritative delegation tracing (root -> TLD -> authoritative). The goals include deterministic behavior, parallelized querying per hop within a time budget, dual output formats (pretty + JSON), and portability as a single static Go binary. The tool must explain failures (NXDOMAIN vs NODATA, broken delegation, lame delegation, SERVFAIL/timeouts) rather than only showing query paths.

## Goals / Non-Goals

**Goals:**
- Provide a resolver-ladder trace that walks configured resolvers (system by default) and shows where answers appear or fail.
- Implement iterative delegation tracing: root -> TLD -> authoritative for a given name + RRtype.
- Follow CNAME/DNAME chains with a bounded hop limit.
- Provide clear, evidence-backed diagnostics for failures.
- Parallelize candidate nameserver queries per hop with deterministic selection rules.
- Produce both human-readable and JSON outputs.
- Ship as a portable, single static Go binary.

**Non-Goals:**
- Full recursive caching resolver behavior.
- System resolver configuration management.
- Zone transfers or dynamic DNS updates.

## Decisions

1. **Language and core libraries**
   - Use Go for a static binary and easy cross-compilation.
   - Use `miekg/dns` for DNS message construction/parsing.
   - Alternatives: `net/dns` or raw sockets. Rejected due to limited control over EDNS0, message parsing, and retry logic.

2. **CLI shape**
   - Default command runs resolver-ladder mode: `dnstrace <fqdn> [rrtype]`.
   - Authoritative trace is a subcommand: `dnstrace trace <fqdn> [rrtype]`.

3. **Package structure**
   - `cmd/dnstrace`: CLI parsing, wiring, exit codes.
   - `internal/dnsclient`: message building, UDP/TCP transport, retries, EDNS0, timeouts.
   - `internal/trace`: iterative delegation walk, zone cut detection, and next-authority selection.
   - `internal/analyze`: classification and evidence generation for outcomes.
   - Rationale: isolates transport, traversal, and analysis to keep logic testable and independent.

4. **Query strategy and determinism**
   - Resolver-ladder mode uses recursive queries (RD=1) against each configured resolver to show resolver view. The default ladder is system resolvers followed by a small set of public resolvers for upstream comparison, and the ladder continues even when earlier resolvers return answers.
   - Authoritative trace uses RD=0 and a built-in root hints list to seed the trace.
   - At each hop in authoritative trace, query candidate NS in parallel (bounded by `parallelism` and `max_time`).
   - Deterministic selection rules: prefer authoritative answers (AA=1), complete NS sets, and lowest latency among consistent answers. This keeps output stable without ignoring fast failures.
   - Output is summarized by default (one step per hop with aggregated response counts); verbose mode emits per-nameserver responses.
   - Alternatives: query sequentially (slower) or random selection (non-deterministic). Rejected for operator usability.

4. **CNAME/DNAME handling**
   - Follow CNAME/DNAME chains, tracking visited names and enforcing `max_hops` to prevent loops.
   - Each hop produces an explicit trace step showing the redirect reason.

5. **Failure classification logic**
   - Use response RCODE + presence of SOA/NS to distinguish NXDOMAIN vs NODATA.
   - Broken delegation: no reachable NS for a delegation (timeouts, missing glue, or unreachable servers).
   - Lame delegation: NS responds but not authoritative or for the wrong zone.
   - SERVFAIL/timeouts: report and include hints (e.g., TCP fallback attempted, EDNS0 size adjustments).
   - Alternatives: only emit raw trace and let users interpret. Rejected; diagnostics are core value.

6. **Output formats**
   - Pretty output using `lipgloss` with aligned trace steps and a summary diagnosis.
   - JSON output containing `trace_steps`, `diagnosis`, and `timings` for integration and automation.
   - Ensure both outputs contain the same underlying data model.

7. **Logging and debug**
   - Use `zap` for verbose/debug modes, including raw DNS messages when enabled.
   - Default output remains clean; logs are opt-in.

## Risks / Trade-offs

- **Parallel querying can surface inconsistent answers** → Apply deterministic selection rules and still record diverging responses in trace steps.
- **Anycast or transient failures may produce flaky results** → Prefer majority/consistent answers and expose timings/timeout info.
- **EDNS0/UDP size issues and truncation** → Implement TCP fallback and record when it happens.
- **Diagnostic rules may misclassify edge cases** → Include evidence (RCODE/AA/SOA/NS) so users can verify; keep rule set simple and explicit.

## Migration Plan

- New tool with no existing users; no migration required.
- Release a single static binary via standard distribution (e.g., GitHub releases).
- Rollback is simply reverting to prior releases.

## Open Questions

- Root hints source and update mechanism (static list vs periodic update).
- DNSSEC behavior: only display RRSIG/DO bit metadata or attempt validation when `--dnssec` is enabled.
- JSON schema details for `trace_steps` and `diagnosis` (to be finalized in specs).
