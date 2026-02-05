## Why

DNS delegation failures are opaque with standard resolver tooling; `dig +trace` shows the path but not the cause. We need a purpose-built trace tool that explains *why* resolution fails so operators can quickly isolate delegation, glue, or authority problems.

## What Changes

- Add a new CLI tool `dnstrace` that performs iterative DNS delegation tracing (root -> TLD -> authoritative) for a name + RRtype.
- Follow CNAME/DNAME chains where applicable during tracing.
- Diagnose and explain failures (NXDOMAIN vs NODATA, broken delegation/missing glue, lame delegation, SERVFAIL/timeouts) with evidence.
- Emit a clear, evidence-based trace report showing which server said what (including SOA/NS when relevant).

## Capabilities

### New Capabilities
- `delegation-trace`: Perform iterative delegation tracing for a specific name and RRtype, including CNAME/DNAME following.
- `diagnostic-reporting`: Classify resolution failures and produce evidence-backed diagnostics in trace output.

### Modified Capabilities
- (none)

## Impact

- New CLI entrypoint and supporting packages for DNS querying and trace orchestration.
- New diagnostic/reporting output format.
- Documentation updates for usage and examples.
