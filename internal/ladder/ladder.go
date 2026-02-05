package ladder

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jaxxstorm/dnstrace/internal/analyze"
	"github.com/jaxxstorm/dnstrace/internal/dnsclient"
	"github.com/jaxxstorm/dnstrace/internal/model"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type Config struct {
	Timeout time.Duration
	Logger  *zap.Logger
}

func Trace(ctx context.Context, client *dnsclient.Client, resolvers []string, fqdn string, rrtype string, cfg Config) (model.TraceResult, error) {
	qtype, ok := dns.StringToType[strings.ToUpper(rrtype)]
	if !ok {
		return model.TraceResult{}, fmt.Errorf("unsupported rrtype: %s", rrtype)
	}
	if len(resolvers) == 0 {
		return model.TraceResult{}, fmt.Errorf("no resolvers configured")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}

	result := model.TraceResult{}
	for i, resolver := range resolvers {
		resolver = dnsclient.NormalizeServer(resolver)
		query := client.BuildQuery(fqdn, qtype)
		query.RecursionDesired = true

		ctxReq, cancel := context.WithTimeout(ctx, cfg.Timeout)
		resp, rtt, transport, err := client.Exchange(ctxReq, resolver, query)
		cancel()

		step := model.TraceStep{
			Index:     i,
			Server:    resolver,
			QueryName: dns.Fqdn(fqdn),
			QueryType: dns.TypeToString[qtype],
			Transport: transport,
			RTT:       rtt.String(),
			Timestamp: time.Now(),
		}

		if err != nil {
			step.Error = err.Error()
			result.TraceSteps = append(result.TraceSteps, step)
			result.Timings = append(result.Timings, model.Timing{StepIndex: i, Server: resolver, RTT: rtt.String(), TimedOut: true, Transport: transport})
			continue
		}

		if resp != nil {
			step.Authoritative = resp.Authoritative
			step.Rcode = dns.RcodeToString[resp.Rcode]
			step.Answers = rrStrings(resp.Answer)
			step.NS = nsStrings(resp.Ns)
			step.SOA = soaString(resp)
			if isReferral(resp) {
				step.Note = "referral (expected at delegation level)"
			}
		}

		result.TraceSteps = append(result.TraceSteps, step)
		result.Timings = append(result.Timings, model.Timing{StepIndex: i, Server: resolver, RTT: rtt.String(), TimedOut: false, Transport: transport})
	}

	result.Diagnosis = diagnoseLadder(result)
	return result, nil
}

func diagnoseLadder(result model.TraceResult) model.Diagnosis {
	firstAnswer := -1
	firstNX := -1
	firstNoData := -1
	firstServfail := -1
	for _, step := range result.TraceSteps {
		if step.Error != "" {
			if firstServfail == -1 {
				firstServfail = step.Index
			}
			continue
		}
		if hasAnswer(step) {
			if firstAnswer == -1 {
				firstAnswer = step.Index
			}
		}
		switch step.Rcode {
		case "NXDOMAIN":
			if firstNX == -1 {
				firstNX = step.Index
			}
		case "NOERROR":
			if !hasAnswer(step) && firstNoData == -1 {
				firstNoData = step.Index
			}
		case "SERVFAIL", "REFUSED":
			if firstServfail == -1 {
				firstServfail = step.Index
			}
		}
	}

	switch {
	case firstAnswer >= 0:
		return analyze.Diagnose(analyze.Outcome{Kind: analyze.OutcomeSuccess, Summary: "resolver returned answer", EvidenceStep: firstAnswer})
	case firstNX >= 0:
		return analyze.Diagnose(analyze.Outcome{Kind: analyze.OutcomeNXDOMAIN, Summary: "resolver returned NXDOMAIN", EvidenceStep: firstNX})
	case firstNoData >= 0:
		return analyze.Diagnose(analyze.Outcome{Kind: analyze.OutcomeNODATA, Summary: "resolver returned NOERROR without data", EvidenceStep: firstNoData})
	case firstServfail >= 0:
		return analyze.Diagnose(analyze.Outcome{Kind: analyze.OutcomeServfailTimeout, Summary: "resolver failure or timeout", EvidenceStep: firstServfail})
	default:
		return analyze.Diagnose(analyze.Outcome{Kind: analyze.OutcomeServfailTimeout, Summary: "no resolver responses", EvidenceStep: -1})
	}
}

func hasAnswer(step model.TraceStep) bool {
	return len(step.Answers) > 0
}

func isReferral(resp *dns.Msg) bool {
	return resp != nil && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 && len(resp.Ns) > 0
}

func nsStrings(rrs []dns.RR) []string {
	out := []string{}
	for _, rr := range rrs {
		if ns, ok := rr.(*dns.NS); ok {
			out = append(out, ns.Ns)
		}
	}
	return out
}

func rrStrings(rrs []dns.RR) []string {
	out := []string{}
	for _, rr := range rrs {
		out = append(out, rr.String())
	}
	return out
}

func soaString(resp *dns.Msg) string {
	for _, rr := range resp.Ns {
		if _, ok := rr.(*dns.SOA); ok {
			return rr.String()
		}
	}
	return ""
}
