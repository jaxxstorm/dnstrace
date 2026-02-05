package model

import "time"

type TraceStep struct {
	Index         int       `json:"index"`
	Server        string    `json:"server"`
	ServerName    string    `json:"server_name,omitempty"`
	QueryName     string    `json:"query_name"`
	QueryType     string    `json:"query_type"`
	Transport     string    `json:"transport"`
	Rcode         string    `json:"rcode"`
	Authoritative bool      `json:"authoritative"`
	Answers       []string  `json:"answers,omitempty"`
	NS            []string  `json:"ns,omitempty"`
	SOA           string    `json:"soa,omitempty"`
	RTT           string    `json:"rtt"`
	Error         string    `json:"error,omitempty"`
	Note          string    `json:"note,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

type Timing struct {
	StepIndex int    `json:"step_index"`
	Server    string `json:"server"`
	RTT       string `json:"rtt"`
	TimedOut  bool   `json:"timed_out"`
	Transport string `json:"transport"`
}

type Diagnosis struct {
	Classification string   `json:"classification"`
	Summary        string   `json:"summary"`
	EvidenceSteps  []int    `json:"evidence_steps"`
	Hints          []string `json:"hints,omitempty"`
}

type TraceResult struct {
	TraceSteps []TraceStep `json:"trace_steps"`
	Diagnosis  Diagnosis   `json:"diagnosis"`
	Timings    []Timing    `json:"timings"`
}
