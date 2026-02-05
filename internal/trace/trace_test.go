package trace

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jaxxstorm/dnstrace/internal/dnsclient"
	"github.com/miekg/dns"
)

func TestTraceDelegationSuccess(t *testing.T) {
	transport := &dnsclient.MockTransport{Responder: func(server string, msg *dns.Msg) (*dns.Msg, time.Duration, error) {
		q := msg.Question[0]
		switch server {
		case "1.1.1.1:53":
			resp := new(dns.Msg)
			resp.SetReply(msg)
			resp.Authoritative = false
			resp.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "ns1.com."}}
			resp.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns1.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")}}
			return resp, 10 * time.Millisecond, nil
		case "192.0.2.1:53":
			resp := new(dns.Msg)
			resp.SetReply(msg)
			resp.Authoritative = false
			resp.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "ns1.example.com."}}
			resp.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.53")}}
			return resp, 12 * time.Millisecond, nil
		case "192.0.2.53:53":
			if q.Name != "api.example.com." {
				return nil, 0, errors.New("unexpected qname")
			}
			resp := new(dns.Msg)
			resp.SetReply(msg)
			resp.Authoritative = true
			resp.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("203.0.113.10")}}
			return resp, 8 * time.Millisecond, nil
		default:
			return nil, 0, errors.New("unexpected server")
		}
	}}

	client := dnsclient.NewWithTransports(dnsclient.Options{Mode: dnsclient.ModeUDP, Timeout: time.Second}, transport, transport)
	tracer := NewTracer(client, Config{MaxHops: 5, MaxTime: time.Second, Parallelism: 2})
	tracer.rootHints = []string{"1.1.1.1:53"}

	result, err := tracer.Trace(context.Background(), "api.example.com", "A")
	if err != nil {
		t.Fatalf("trace error: %v", err)
	}
	if result.Diagnosis.Classification != "SUCCESS" {
		t.Fatalf("expected SUCCESS, got %s", result.Diagnosis.Classification)
	}
}

func TestTraceFollowsCNAME(t *testing.T) {
	transport := &dnsclient.MockTransport{Responder: func(server string, msg *dns.Msg) (*dns.Msg, time.Duration, error) {
		q := msg.Question[0]
		switch server {
		case "1.1.1.1:53":
			resp := new(dns.Msg)
			resp.SetReply(msg)
			resp.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "ns1.com."}}
			resp.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns1.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")}}
			return resp, 10 * time.Millisecond, nil
		case "192.0.2.1:53":
			resp := new(dns.Msg)
			resp.SetReply(msg)
			resp.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "ns1.example.com."}}
			resp.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.53")}}
			return resp, 12 * time.Millisecond, nil
		case "192.0.2.53:53":
			resp := new(dns.Msg)
			resp.SetReply(msg)
			resp.Authoritative = true
			if q.Name == "www.example.com." {
				resp.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "edge.example.com."}}
				return resp, 8 * time.Millisecond, nil
			}
			if q.Name == "edge.example.com." {
				resp.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("203.0.113.20")}}
				return resp, 8 * time.Millisecond, nil
			}
			return nil, 0, errors.New("unexpected qname")
		default:
			return nil, 0, errors.New("unexpected server")
		}
	}}

	client := dnsclient.NewWithTransports(dnsclient.Options{Mode: dnsclient.ModeUDP, Timeout: time.Second}, transport, transport)
	tracer := NewTracer(client, Config{MaxHops: 5, MaxTime: time.Second, Parallelism: 2})
	tracer.rootHints = []string{"1.1.1.1:53"}

	result, err := tracer.Trace(context.Background(), "www.example.com", "A")
	if err != nil {
		t.Fatalf("trace error: %v", err)
	}
	if result.Diagnosis.Classification != "SUCCESS" {
		t.Fatalf("expected SUCCESS, got %s", result.Diagnosis.Classification)
	}
}
