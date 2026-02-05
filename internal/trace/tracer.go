package trace

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jaxxstorm/dnstrace/internal/analyze"
	"github.com/jaxxstorm/dnstrace/internal/dnsclient"
	"github.com/jaxxstorm/dnstrace/internal/model"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type Config struct {
	MaxHops     int
	MaxTime     time.Duration
	Parallelism int
	Logger      *zap.Logger
	Verbose     bool
}

type Tracer struct {
	client    *dnsclient.Client
	config    Config
	rootHints []string
}

type response struct {
	server    string
	resp      *dns.Msg
	rtt       time.Duration
	transport string
	err       error
	stepIndex int
}

func NewTracer(client *dnsclient.Client, cfg Config) *Tracer {
	if cfg.MaxHops == 0 {
		cfg.MaxHops = 32
	}
	if cfg.MaxTime == 0 {
		cfg.MaxTime = 2 * time.Second
	}
	if cfg.Parallelism == 0 {
		cfg.Parallelism = 6
	}
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}
	return &Tracer{client: client, config: cfg, rootHints: DefaultRootHints}
}

func (t *Tracer) Trace(ctx context.Context, fqdn string, rrtype string) (model.TraceResult, error) {
	qtype, ok := dns.StringToType[strings.ToUpper(rrtype)]
	if !ok {
		return model.TraceResult{}, fmt.Errorf("unsupported rrtype: %s", rrtype)
	}

	name := dns.Fqdn(fqdn)
	servers := append([]string{}, t.rootHints...)
	serverLabels := map[string]string{}
	for addr, name := range DefaultRootHintNames {
		serverLabels[addr] = name
	}
	visited := map[string]bool{}

	result := model.TraceResult{}

	for hop := 0; hop < t.config.MaxHops; hop++ {
		responses := t.queryServers(ctx, servers, name, qtype, &result, t.config.Verbose, serverLabels)
		best := selectBest(responses, qtype)
		if best == nil {
			outcome := analyze.Outcome{
				Kind:         analyze.OutcomeServfailTimeout,
				Summary:      "no reachable nameservers for delegation",
				EvidenceStep: latestStepIndex(result.TraceSteps),
				Hints:        []string{"check network reachability or nameserver availability"},
			}
			result.Diagnosis = analyze.Diagnose(outcome)
			return result, nil
		}

		if best.err != nil {
			outcome := analyze.Outcome{
				Kind:         analyze.OutcomeServfailTimeout,
				Summary:      best.err.Error(),
				EvidenceStep: best.stepIndex,
				Hints:        []string{"retry with --transport tcp", "verify nameserver reachability"},
			}
			result.Diagnosis = analyze.Diagnose(outcome)
			return result, nil
		}

		if !t.config.Verbose {
			stepIndex := len(result.TraceSteps)
			step := buildStep(stepIndex, name, qtype, *best, serverLabels)
			step.Note = summarizeResponses(responses)
			if best.resp != nil && hasDelegation(best.resp) {
				_, zone := nsNamesAndZone(best.resp)
				if zone != "" {
					step.Note = appendNote(step.Note, fmt.Sprintf("referral=%s", zone))
				}
			}
			result.TraceSteps = append(result.TraceSteps, step)
			result.Timings = append(result.Timings, buildTiming(stepIndex, *best))
			best.stepIndex = stepIndex
		}

		resp := best.resp
		if resp == nil {
			outcome := analyze.Outcome{
				Kind:         analyze.OutcomeServfailTimeout,
				Summary:      "empty response from nameserver",
				EvidenceStep: best.stepIndex,
				Hints:        []string{"retry with --transport tcp"},
			}
			result.Diagnosis = analyze.Diagnose(outcome)
			return result, nil
		}

		if resp.Rcode == dns.RcodeNameError && resp.Authoritative {
			outcome := analyze.Outcome{
				Kind:         analyze.OutcomeNXDOMAIN,
				Summary:      "authoritative NXDOMAIN",
				EvidenceStep: best.stepIndex,
			}
			result.Diagnosis = analyze.Diagnose(outcome)
			return result, nil
		}

		if resp.Rcode == dns.RcodeSuccess {
			if hasAnswerType(resp, qtype) && resp.Authoritative {
				outcome := analyze.Outcome{
					Kind:         analyze.OutcomeSuccess,
					Summary:      "authoritative answer returned",
					EvidenceStep: best.stepIndex,
				}
				result.Diagnosis = analyze.Diagnose(outcome)
				return result, nil
			}

			if cname := firstCNAME(resp); cname != nil {
				if visited[cname.Target] {
					outcome := analyze.Outcome{
						Kind:         analyze.OutcomeServfailTimeout,
						Summary:      "CNAME loop detected",
						EvidenceStep: best.stepIndex,
						Hints:        []string{"verify CNAME chain"},
					}
					result.Diagnosis = analyze.Diagnose(outcome)
					return result, nil
				}
				visited[cname.Target] = true
				name = dns.Fqdn(cname.Target)
				continue
			}

			if dname := firstDNAME(resp); dname != nil {
				newName, err := applyDNAME(name, dname.Hdr.Name, dname.Target)
				if err != nil {
					outcome := analyze.Outcome{
						Kind:         analyze.OutcomeServfailTimeout,
						Summary:      err.Error(),
						EvidenceStep: best.stepIndex,
					}
					result.Diagnosis = analyze.Diagnose(outcome)
					return result, nil
				}
				if visited[newName] {
					outcome := analyze.Outcome{
						Kind:         analyze.OutcomeServfailTimeout,
						Summary:      "DNAME loop detected",
						EvidenceStep: best.stepIndex,
						Hints:        []string{"verify DNAME chain"},
					}
					result.Diagnosis = analyze.Diagnose(outcome)
					return result, nil
				}
				visited[newName] = true
				name = dns.Fqdn(newName)
				continue
			}

			if resp.Authoritative && hasSOA(resp) && !hasAnswerType(resp, qtype) {
				outcome := analyze.Outcome{
					Kind:         analyze.OutcomeNODATA,
					Summary:      "authoritative no data for RRtype",
					EvidenceStep: best.stepIndex,
				}
				result.Diagnosis = analyze.Diagnose(outcome)
				return result, nil
			}

			if hasDelegation(resp) {
				nextServers := extractGlueServers(resp)
				nextLabels := extractGlueLabels(resp)
				if len(nextServers) == 0 {
					nsNames, zone := nsNamesAndZone(resp)
					inBailiwick, outOfBailiwick := splitBailiwick(nsNames, zone)
					resolved := []string{}
					var err error
					if len(outOfBailiwick) > 0 {
						resolved, err = t.resolveNameserverAddresses(ctx, outOfBailiwick, &result, 0, t.config.Verbose)
					}
					if err == nil && len(resolved) > 0 {
						servers = resolved
						if len(nextLabels) > 0 {
							serverLabels = nextLabels
						}
						continue
					}

					hints := []string{}
					if len(inBailiwick) > 0 {
						hints = append(hints, "missing glue records for in-bailiwick nameservers")
					}
					if len(outOfBailiwick) > 0 {
						hints = append(hints, "unable to resolve out-of-bailiwick nameserver addresses")
					}
					outcome := analyze.Outcome{
						Kind:         analyze.OutcomeBrokenDelegation,
						Summary:      "delegation without glue",
						EvidenceStep: best.stepIndex,
						Hints:        hints,
					}
					result.Diagnosis = analyze.Diagnose(outcome)
					return result, nil
				}
				servers = nextServers
				if len(nextLabels) > 0 {
					serverLabels = nextLabels
				}
				continue
			}

			if !resp.Authoritative {
				outcome := analyze.Outcome{
					Kind:         analyze.OutcomeLameDelegation,
					Summary:      "nameserver not authoritative for zone",
					EvidenceStep: best.stepIndex,
					Hints:        []string{"verify NS delegation and authoritative configuration"},
				}
				result.Diagnosis = analyze.Diagnose(outcome)
				return result, nil
			}
		}

		if resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
			outcome := analyze.Outcome{
				Kind:         analyze.OutcomeServfailTimeout,
				Summary:      dns.RcodeToString[resp.Rcode],
				EvidenceStep: best.stepIndex,
				Hints:        []string{"check authoritative server health"},
			}
			result.Diagnosis = analyze.Diagnose(outcome)
			return result, nil
		}
	}

	outcome := analyze.Outcome{
		Kind:         analyze.OutcomeServfailTimeout,
		Summary:      "max hops exceeded",
		EvidenceStep: latestStepIndex(result.TraceSteps),
		Hints:        []string{"increase --max-hops", "check for CNAME loops"},
	}
	result.Diagnosis = analyze.Diagnose(outcome)
	return result, nil
}

func (t *Tracer) resolveNameserverAddresses(ctx context.Context, names []string, result *model.TraceResult, depth int, record bool) ([]string, error) {
	if depth > 4 {
		return nil, fmt.Errorf("nameserver resolution depth exceeded")
	}
	addresses := []string{}
	for _, name := range names {
		aAddrs, err := t.resolveHost(ctx, name, dns.TypeA, result, depth, record)
		if err == nil {
			addresses = append(addresses, aAddrs...)
		}
		aaaaAddrs, err := t.resolveHost(ctx, name, dns.TypeAAAA, result, depth, record)
		if err == nil {
			addresses = append(addresses, aaaaAddrs...)
		}
	}
	addresses = uniqueStrings(addresses)
	if len(addresses) == 0 {
		return nil, fmt.Errorf("unable to resolve nameserver addresses")
	}
	return addresses, nil
}

func (t *Tracer) resolveHost(ctx context.Context, name string, qtype uint16, result *model.TraceResult, depth int, record bool) ([]string, error) {
	name = dns.Fqdn(name)
	servers := append([]string{}, t.rootHints...)
	serverLabels := map[string]string{}
	for addr, label := range DefaultRootHintNames {
		serverLabels[addr] = label
	}
	visited := map[string]bool{}

	for hop := 0; hop < t.config.MaxHops; hop++ {
		responses := t.queryServers(ctx, servers, name, qtype, result, record, serverLabels)
		best := selectBest(responses, qtype)
		if best == nil || best.resp == nil || best.err != nil {
			return nil, fmt.Errorf("no reachable nameservers for %s", name)
		}
		resp := best.resp
		if resp.Rcode == dns.RcodeNameError && resp.Authoritative {
			return nil, fmt.Errorf("nxdomain for %s", name)
		}
		if resp.Rcode == dns.RcodeSuccess {
			if resp.Authoritative && hasAnswerType(resp, qtype) {
				return extractAddresses(resp, qtype), nil
			}
			if cname := firstCNAME(resp); cname != nil {
				if visited[cname.Target] {
					return nil, fmt.Errorf("cname loop for %s", cname.Target)
				}
				visited[cname.Target] = true
				name = dns.Fqdn(cname.Target)
				continue
			}
			if dname := firstDNAME(resp); dname != nil {
				newName, err := applyDNAME(name, dname.Hdr.Name, dname.Target)
				if err != nil {
					return nil, err
				}
				if visited[newName] {
					return nil, fmt.Errorf("dname loop for %s", newName)
				}
				visited[newName] = true
				name = dns.Fqdn(newName)
				continue
			}
			if hasDelegation(resp) {
				nextServers := extractGlueServers(resp)
				nextLabels := extractGlueLabels(resp)
				if len(nextServers) == 0 {
					nsNames, zone := nsNamesAndZone(resp)
					inBailiwick, outOfBailiwick := splitBailiwick(nsNames, zone)
					if len(outOfBailiwick) == 0 && len(inBailiwick) > 0 {
						return nil, fmt.Errorf("delegation without glue for %s", zone)
					}
					resolved, err := t.resolveNameserverAddresses(ctx, outOfBailiwick, result, depth+1, record)
					if err != nil {
						return nil, err
					}
					servers = resolved
					serverLabels = nextLabels
					continue
				}
				servers = nextServers
				if len(nextLabels) > 0 {
					serverLabels = nextLabels
				}
				continue
			}
		}
		if resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
			return nil, fmt.Errorf("server failure for %s", name)
		}
	}
	return nil, fmt.Errorf("max hops exceeded for %s", name)
}

func (t *Tracer) queryServers(ctx context.Context, servers []string, name string, qtype uint16, result *model.TraceResult, record bool, serverLabels map[string]string) []response {
	ctx, cancel := context.WithTimeout(ctx, t.config.MaxTime)
	defer cancel()

	responses := make([]response, len(servers))
	wg := sync.WaitGroup{}
	sem := make(chan struct{}, t.config.Parallelism)

	for i, server := range servers {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, srv string) {
			defer wg.Done()
			defer func() { <-sem }()

			msg := t.client.BuildQuery(name, qtype)
			resp, rtt, transport, err := t.client.Exchange(ctx, srv, msg)
			responses[idx] = response{server: srv, resp: resp, rtt: rtt, transport: transport, err: err}
		}(i, server)
	}

	wg.Wait()

	if !record {
		return responses
	}

	for i := range responses {
		stepIndex := len(result.TraceSteps)
		step := buildStep(stepIndex, name, qtype, responses[i], serverLabels)
		result.TraceSteps = append(result.TraceSteps, step)
		result.Timings = append(result.Timings, buildTiming(stepIndex, responses[i]))
		responses[i].stepIndex = stepIndex
	}

	return responses
}

func buildStep(index int, name string, qtype uint16, resp response, serverLabels map[string]string) model.TraceStep {
	step := model.TraceStep{
		Index:         index,
		Server:        resp.server,
		ServerName:    serverLabels[resp.server],
		QueryName:     name,
		QueryType:     dns.TypeToString[qtype],
		Transport:     resp.transport,
		RTT:           resp.rtt.String(),
		Timestamp:     time.Now(),
		Authoritative: resp.resp != nil && resp.resp.Authoritative,
	}
	if resp.err != nil {
		step.Error = resp.err.Error()
		return step
	}
	if resp.resp == nil {
		step.Error = "empty response"
		return step
	}
	step.Rcode = dns.RcodeToString[resp.resp.Rcode]
	step.Answers = rrStrings(resp.resp.Answer)
	step.NS = nsStrings(resp.resp.Ns)
	step.SOA = soaString(resp.resp)
	return step
}

func buildTiming(index int, resp response) model.Timing {
	timedOut := false
	if resp.err != nil && errors.Is(resp.err, context.DeadlineExceeded) {
		timedOut = true
	}
	return model.Timing{
		StepIndex: index,
		Server:    resp.server,
		RTT:       resp.rtt.String(),
		TimedOut:  timedOut,
		Transport: resp.transport,
	}
}

func selectBest(responses []response, qtype uint16) *response {
	valid := make([]response, 0, len(responses))
	for _, r := range responses {
		if r.err == nil && r.resp != nil {
			valid = append(valid, r)
		}
	}
	if len(valid) == 0 {
		return nil
	}
	order := func(r response) int {
		if r.resp.Authoritative && r.resp.Rcode == dns.RcodeSuccess && hasAnswerType(r.resp, qtype) {
			return 0
		}
		if r.resp.Authoritative && r.resp.Rcode == dns.RcodeSuccess {
			return 1
		}
		if r.resp.Authoritative {
			return 2
		}
		if hasDelegation(r.resp) {
			return 3
		}
		if r.resp.Rcode == dns.RcodeNameError {
			return 4
		}
		return 5
	}
	best := valid[0]
	for _, r := range valid[1:] {
		if order(r) < order(best) {
			best = r
			continue
		}
		if order(r) == order(best) {
			if r.rtt < best.rtt {
				best = r
				continue
			}
			if r.rtt == best.rtt && r.server < best.server {
				best = r
			}
		}
	}
	return &best
}

func summarizeResponses(responses []response) string {
	if len(responses) == 0 {
		return ""
	}
	okCount := 0
	timeoutCount := 0
	errorCount := 0
	for _, r := range responses {
		if r.err == nil && r.resp != nil {
			okCount++
			continue
		}
		if r.err != nil && errors.Is(r.err, context.DeadlineExceeded) {
			timeoutCount++
		} else if r.err != nil {
			errorCount++
		}
	}
	return fmt.Sprintf("responses=%d ok=%d timeout=%d error=%d", len(responses), okCount, timeoutCount, errorCount)
}

func appendNote(note string, extra string) string {
	if note == "" {
		return extra
	}
	if extra == "" {
		return note
	}
	return note + " " + extra
}

func hasAnswerType(resp *dns.Msg, qtype uint16) bool {
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == qtype {
			return true
		}
	}
	return false
}

func firstCNAME(resp *dns.Msg) *dns.CNAME {
	for _, rr := range resp.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			return cname
		}
	}
	return nil
}

func firstDNAME(resp *dns.Msg) *dns.DNAME {
	for _, rr := range resp.Answer {
		if dname, ok := rr.(*dns.DNAME); ok {
			return dname
		}
	}
	return nil
}

func hasSOA(resp *dns.Msg) bool {
	return soaString(resp) != ""
}

func soaString(resp *dns.Msg) string {
	for _, rr := range resp.Ns {
		if _, ok := rr.(*dns.SOA); ok {
			return rr.String()
		}
	}
	return ""
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

func hasDelegation(resp *dns.Msg) bool {
	for _, rr := range resp.Ns {
		if _, ok := rr.(*dns.NS); ok {
			return true
		}
	}
	return false
}

func nsNamesAndZone(resp *dns.Msg) ([]string, string) {
	names := []string{}
	zone := ""
	for _, rr := range resp.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			if zone == "" {
				zone = dns.Fqdn(ns.Hdr.Name)
			}
			names = append(names, dns.Fqdn(ns.Ns))
		}
	}
	return uniqueStrings(names), zone
}

func splitBailiwick(nsNames []string, zone string) ([]string, []string) {
	inBailiwick := []string{}
	outOfBailiwick := []string{}
	if zone == "" {
		return inBailiwick, nsNames
	}
	zone = strings.ToLower(dns.Fqdn(zone))
	for _, ns := range nsNames {
		nsLower := strings.ToLower(dns.Fqdn(ns))
		if strings.HasSuffix(nsLower, zone) {
			inBailiwick = append(inBailiwick, nsLower)
		} else {
			outOfBailiwick = append(outOfBailiwick, nsLower)
		}
	}
	return inBailiwick, outOfBailiwick
}

func extractAddresses(resp *dns.Msg, qtype uint16) []string {
	addresses := []string{}
	for _, rr := range resp.Answer {
		switch record := rr.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				addresses = append(addresses, fmt.Sprintf("%s:53", record.A.String()))
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				addresses = append(addresses, fmt.Sprintf("[%s]:53", record.AAAA.String()))
			}
		}
	}
	return uniqueStrings(addresses)
}

func extractGlueServers(resp *dns.Msg) []string {
	nsNames := map[string]struct{}{}
	for _, rr := range resp.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			nsNames[strings.ToLower(ns.Ns)] = struct{}{}
		}
	}
	servers := []string{}
	for _, rr := range resp.Extra {
		switch record := rr.(type) {
		case *dns.A:
			if _, ok := nsNames[strings.ToLower(record.Hdr.Name)]; ok {
				servers = append(servers, fmt.Sprintf("%s:53", record.A.String()))
			}
		case *dns.AAAA:
			if _, ok := nsNames[strings.ToLower(record.Hdr.Name)]; ok {
				servers = append(servers, fmt.Sprintf("[%s]:53", record.AAAA.String()))
			}
		}
	}
	servers = uniqueStrings(servers)
	sort.Strings(servers)
	return servers
}

func extractGlueLabels(resp *dns.Msg) map[string]string {
	nsNames := map[string]string{}
	for _, rr := range resp.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			nsNames[strings.ToLower(ns.Ns)] = dns.Fqdn(ns.Ns)
		}
	}
	labels := map[string]string{}
	for _, rr := range resp.Extra {
		switch record := rr.(type) {
		case *dns.A:
			if name, ok := nsNames[strings.ToLower(record.Hdr.Name)]; ok {
				labels[fmt.Sprintf("%s:53", record.A.String())] = name
			}
		case *dns.AAAA:
			if name, ok := nsNames[strings.ToLower(record.Hdr.Name)]; ok {
				labels[fmt.Sprintf("[%s]:53", record.AAAA.String())] = name
			}
		}
	}
	return labels
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func applyDNAME(name, owner, target string) (string, error) {
	name = dns.Fqdn(name)
	owner = dns.Fqdn(owner)
	if !strings.HasSuffix(name, owner) {
		return "", fmt.Errorf("dname owner %s not suffix of %s", owner, name)
	}
	rest := strings.TrimSuffix(name, owner)
	return rest + dns.Fqdn(target), nil
}

func latestStepIndex(steps []model.TraceStep) int {
	if len(steps) == 0 {
		return -1
	}
	return steps[len(steps)-1].Index
}
