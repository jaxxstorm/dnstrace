package ladder

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jaxxstorm/dnstrace/internal/dnsclient"
	"github.com/miekg/dns"
)

func TestLoadResolversFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	content := "# test\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	resolvers, err := loadResolvers(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(resolvers) != 2 || resolvers[0] != "1.1.1.1" || resolvers[1] != "8.8.8.8" {
		t.Fatalf("unexpected resolvers: %#v", resolvers)
	}
}

func TestLadderTraceUsesResolversInOrder(t *testing.T) {
	transport := &dnsclient.MockTransport{Responder: func(server string, msg *dns.Msg) (*dns.Msg, time.Duration, error) {
		resp := new(dns.Msg)
		resp.SetReply(msg)
		switch server {
		case "1.1.1.1:53":
			resp.Rcode = dns.RcodeNameError
			resp.Authoritative = true
			resp.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}}}
			return resp, 10 * time.Millisecond, nil
		case "8.8.8.8:53":
			resp.Rcode = dns.RcodeSuccess
			resp.Authoritative = true
			resp.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("203.0.113.10")}}
			return resp, 12 * time.Millisecond, nil
		default:
			return nil, 0, nil
		}
	}}

	client := dnsclient.NewWithTransports(dnsclient.Options{Mode: dnsclient.ModeUDP, Timeout: time.Second}, transport, transport)
	result, err := Trace(context.Background(), client, []string{"1.1.1.1", "8.8.8.8"}, "example.com", "A", Config{Timeout: time.Second})
	if err != nil {
		t.Fatalf("trace error: %v", err)
	}
	if len(result.TraceSteps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(result.TraceSteps))
	}
	if result.TraceSteps[0].Server != "1.1.1.1:53" || result.TraceSteps[1].Server != "8.8.8.8:53" {
		t.Fatalf("unexpected servers: %#v", result.TraceSteps)
	}
	if result.Diagnosis.Classification != "SUCCESS" {
		t.Fatalf("expected SUCCESS, got %s", result.Diagnosis.Classification)
	}
}

func TestReferralNote(t *testing.T) {
	transport := &dnsclient.MockTransport{Responder: func(server string, msg *dns.Msg) (*dns.Msg, time.Duration, error) {
		resp := new(dns.Msg)
		resp.SetReply(msg)
		resp.Rcode = dns.RcodeSuccess
		resp.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "ns1.com."}}
		return resp, 5 * time.Millisecond, nil
	}}

	client := dnsclient.NewWithTransports(dnsclient.Options{Mode: dnsclient.ModeUDP, Timeout: time.Second}, transport, transport)
	result, err := Trace(context.Background(), client, []string{"1.1.1.1"}, "example.com", "A", Config{Timeout: time.Second})
	if err != nil {
		t.Fatalf("trace error: %v", err)
	}
	if result.TraceSteps[0].Note == "" {
		t.Fatalf("expected referral note to be set")
	}
}
