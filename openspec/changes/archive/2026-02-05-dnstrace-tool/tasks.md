## 1. Project Setup

- [x] 1.1 Initialize Go module and directory layout (`cmd/dnstrace`, `internal/*`)
- [x] 1.2 Add dependencies (`miekg/dns`, `kong`, `lipgloss`, `zap`)
- [x] 1.3 Define core data models for `trace_steps`, `diagnosis`, and `timings`

## 2. DNS Client Transport

- [x] 2.1 Implement DNS message builder with EDNS0 and RD=0 support
- [x] 2.2 Implement UDP transport with timeouts and retry policy
- [x] 2.3 Implement TCP mode and UDP truncation fallback
- [x] 2.4 Add transport interface and mocks for testing

## 3. Trace Engine

- [x] 3.1 Implement root hints source and seeding logic
- [x] 3.2 Implement delegation walk with zone cut detection and next-NS selection
- [x] 3.3 Implement parallel query fan-out with time budget and deterministic selection rules
- [x] 3.4 Implement CNAME/DNAME following with hop limit and loop detection
- [x] 3.5 Record trace steps with response metadata (RCODE, AA, NS/SOA)

## 4. Diagnostics

- [x] 4.1 Implement outcome classification (SUCCESS, NXDOMAIN, NODATA, BROKEN_DELEGATION, LAME_DELEGATION, SERVFAIL_TIMEOUT)
- [x] 4.2 Implement evidence-backed explanations and failure hints
- [x] 4.3 Populate diagnosis object with evidence step references

## 5. Output and CLI

- [x] 5.1 Implement CLI parsing for `fqdn`, `rrtype`, and flags with `kong`
- [x] 5.2 Implement pretty renderer with `lipgloss` for trace and summary
- [x] 5.3 Implement JSON output encoder for trace steps, diagnosis, and timings
- [x] 5.4 Add verbose/debug logging with `zap`, including raw DNS messages

## 6. Tests and Docs

- [x] 6.1 Add unit tests for dnsclient transport and fallback behavior
- [x] 6.2 Add unit tests for trace engine (delegation, CNAME/DNAME, parallel selection)
- [x] 6.3 Add unit tests for diagnostics classification and evidence mapping
- [x] 6.4 Document CLI usage and example outputs (pretty and JSON)

## 7. Resolver Ladder Core Mode

- [x] 7.1 Implement resolver-ladder flow that queries configured resolvers sequentially
- [x] 7.2 Load system resolvers when no resolver list is provided
- [x] 7.3 Add resolver list flag (dig-style, but flag-based) and include resolver IPs in trace steps
- [x] 7.4 Annotate referral-only responses as expected in output
- [x] 7.5 Add tests for resolver-ladder behavior and resolver selection
- [x] 7.6 Include default public resolvers after system resolvers when no resolver list is provided
- [x] 7.7 Render answer values in pretty output and continue querying all resolvers

## 8. Authoritative Trace Output

- [x] 8.1 Summarize authoritative hops by default with aggregated response counts
- [x] 8.2 Emit full per-nameserver responses in verbose mode
- [x] 8.3 Display known nameserver hostnames alongside IPs
