package dnsclient

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

type Transport interface {
	Exchange(ctx context.Context, server string, msg *dns.Msg) (*dns.Msg, time.Duration, error)
}

type udpTransport struct {
	timeout time.Duration
}

func (t *udpTransport) Exchange(ctx context.Context, server string, msg *dns.Msg) (*dns.Msg, time.Duration, error) {
	client := &dns.Client{Net: "udp", Timeout: t.timeout}
	if deadline, ok := ctx.Deadline(); ok {
		client.Timeout = time.Until(deadline)
	}
	return client.Exchange(msg, server)
}

type tcpTransport struct {
	timeout time.Duration
}

func (t *tcpTransport) Exchange(ctx context.Context, server string, msg *dns.Msg) (*dns.Msg, time.Duration, error) {
	client := &dns.Client{Net: "tcp", Timeout: t.timeout}
	if deadline, ok := ctx.Deadline(); ok {
		client.Timeout = time.Until(deadline)
	}
	return client.Exchange(msg, server)
}
