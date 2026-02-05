## ADDED Requirements

### Requirement: Outcome classification
The system SHALL classify the trace outcome as one of: SUCCESS, NXDOMAIN, NODATA, BROKEN_DELEGATION, LAME_DELEGATION, or SERVFAIL_TIMEOUT.

#### Scenario: NXDOMAIN classification
- **WHEN** the authoritative response returns NXDOMAIN with an SOA in authority
- **THEN** the system classifies the outcome as NXDOMAIN

#### Scenario: NODATA classification
- **WHEN** the authoritative response returns NOERROR with an SOA in authority and no matching RRset
- **THEN** the system classifies the outcome as NODATA

### Requirement: Evidence-backed explanation
The system SHALL provide a human-readable explanation that references specific trace steps, and SHALL include the evidence used for classification (RCODE, AA bit, SOA/NS records, timeouts).

#### Scenario: Explanation references evidence
- **WHEN** a trace fails due to a lame delegation
- **THEN** the output explains which server was non-authoritative and references the related trace steps and response flags

### Requirement: Diagnostic hints for failures
The system SHALL include actionable hints for SERVFAIL or timeout outcomes, such as transport fallback attempts or unreachable nameservers.

#### Scenario: Timeout includes hint
- **WHEN** all candidate nameservers time out within the hop time budget
- **THEN** the system includes a hint indicating timeouts and which servers were attempted

### Requirement: Structured diagnosis output
The system SHALL emit a machine-readable diagnosis object that includes classification, summary text, and references to trace step indices.

#### Scenario: JSON includes diagnosis data
- **WHEN** output format is JSON
- **THEN** the diagnosis object includes `classification`, `summary`, and `evidence_steps` fields
