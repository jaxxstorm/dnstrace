## ADDED Requirements

### Requirement: Iterative non-recursive trace
The system SHALL perform an iterative DNS delegation trace for the requested FQDN and RRtype using non-recursive queries (RD=0), starting from root hints and following delegation to the authoritative zone.

#### Scenario: Trace starts at root and walks delegations
- **WHEN** the user requests a trace for `api.example.com` type `A`
- **THEN** the system sends RD=0 queries beginning at a root server and continues via delegated NS until the authoritative zone is reached or the trace fails

### Requirement: CNAME and DNAME following
The system SHALL follow CNAME and DNAME aliases encountered during tracing, and SHALL stop if `max_hops` is exceeded or a loop is detected.

#### Scenario: CNAME chain is followed with hop limit
- **WHEN** a response includes a CNAME to another name
- **THEN** the system traces the target name and halts with a clear failure if the hop limit is exceeded or a loop is detected

### Requirement: Parallel nameserver querying per hop
The system SHALL query candidate nameservers in parallel up to the configured `parallelism` and within `max_time` to determine the best consistent answer for the hop.

#### Scenario: Parallel querying selects consistent answers
- **WHEN** multiple nameservers are available for a delegation
- **THEN** the system queries them in parallel within the time budget and chooses a consistent authoritative answer to continue the trace

### Requirement: Transport handling and retries
The system SHALL support UDP, TCP, and auto transport modes, and SHALL retry or fallback as needed to complete each hop within the configured limits.

#### Scenario: UDP truncation triggers TCP fallback
- **WHEN** a UDP response is truncated
- **THEN** the system retries the query over TCP before declaring a failure

### Requirement: Trace step recording
The system SHALL record each query/response as an ordered trace step including server address, query name/type, response code, AA bit, and relevant NS/SOA records if present, and SHALL expose all steps when verbose mode is enabled.

#### Scenario: Trace step captures evidence
- **WHEN** a nameserver responds to a query
- **THEN** the system records the server, query, response metadata, and relevant NS/SOA data in the trace steps

### Requirement: Authoritative trace summary by default
The authoritative trace output SHALL summarize each hop with a single representative response by default, and SHALL include aggregate response counts (ok/timeout/error) as a note.

#### Scenario: Summarized authoritative hop output
- **WHEN** the authoritative trace queries multiple nameservers at a hop
- **THEN** the output includes one step with the selected response and a note showing aggregated response counts

#### Scenario: Verbose authoritative output
- **WHEN** the user enables verbose mode
- **THEN** the output includes all per-nameserver responses for each hop

### Requirement: Nameserver label display
The authoritative trace output SHALL include the nameserver hostname for a server IP when it is known (eg. from root hints or glue records).

#### Scenario: Server name is shown
- **WHEN** a response comes from a server IP that maps to an NS hostname
- **THEN** the output includes the NS hostname alongside the IP

### Requirement: Default RRtype
The system SHALL default the RRtype to `A` when the user does not specify a record type.

#### Scenario: RRtype omitted defaults to A
- **WHEN** the user runs `dnstrace example.com` without a record type
- **THEN** the system performs an `A` record trace

### Requirement: Resolver ladder core mode
The system SHALL perform a resolver-ladder trace by default, querying a sequence of resolvers to determine where answers appear or disappear for the requested name and RRtype.

#### Scenario: Uses system resolvers by default
- **WHEN** the user runs `dnstrace example.com` without specifying resolver servers
- **THEN** the system uses the OS-configured resolvers as the starting resolver list

#### Scenario: Uses configured resolver list
- **WHEN** the user provides a resolver list via a flag
- **THEN** the system queries those resolvers in the provided order instead of the system default

#### Scenario: Default chain includes upstream public resolvers
- **WHEN** the user does not provide a resolver list
- **THEN** the system appends a default set of public resolvers after the system resolvers to check upstream behavior

### Requirement: Resolver IP logging
The system SHALL include the resolver IP address for each resolver-ladder step in the trace output.

#### Scenario: Resolver IP is recorded
- **WHEN** a resolver responds during the ladder trace
- **THEN** the trace step includes the resolver IP address used for that query

### Requirement: Resolver ladder continues after answers
The system SHALL query all resolvers in the configured ladder even if an earlier resolver returns an answer.

#### Scenario: Queries continue upstream after answer
- **WHEN** the first resolver returns an answer
- **THEN** the system still queries subsequent resolvers in the ladder and records their responses

### Requirement: Answer value output
The system SHALL include returned answer records in the trace output when present.

#### Scenario: Answers are displayed
- **WHEN** a resolver returns answer records
- **THEN** the output includes the answer values alongside the trace step

### Requirement: Referral annotation
The system SHALL label delegation-only responses (referrals) as expected for that level and SHALL NOT treat them as failures.

#### Scenario: Root referral is labeled as expected
- **WHEN** a root server returns a referral with NS records and no answer
- **THEN** the trace step is annotated as a referral expected at the root/TLD level
