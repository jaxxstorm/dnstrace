package dnsclient

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestAutoFallbackToTCPOnTruncation(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if w.RemoteAddr().Network() == "udp" {
			m.Truncated = true
			_ = w.WriteMsg(m)
			return
		}
		m.Authoritative = true
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.10"),
		})
		_ = w.WriteMsg(m)
	})

	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	defer udpConn.Close()

	addr := udpConn.LocalAddr().String()
	tcpLn, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	defer tcpLn.Close()

	udpSrv := &dns.Server{PacketConn: udpConn, Handler: mux}
	tcpSrv := &dns.Server{Listener: tcpLn, Handler: mux}

	go func() { _ = udpSrv.ActivateAndServe() }()
	go func() { _ = tcpSrv.ActivateAndServe() }()
	defer udpSrv.Shutdown()
	defer tcpSrv.Shutdown()

	client := New(Options{Mode: ModeAuto, Timeout: 500 * time.Millisecond})
	msg := client.BuildQuery("example.com.", dns.TypeA)
	resp, _, transport, err := client.Exchange(context.Background(), addr, msg)
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if transport != "tcp" {
		t.Fatalf("expected tcp transport, got %s", transport)
	}
	if resp == nil || len(resp.Answer) == 0 {
		t.Fatalf("expected answer after tcp fallback")
	}
}
