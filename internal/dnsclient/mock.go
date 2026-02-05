package dnsclient

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

type MockTransport struct {
	Responder func(server string, msg *dns.Msg) (*dns.Msg, time.Duration, error)
}

func (m *MockTransport) Exchange(ctx context.Context, server string, msg *dns.Msg) (*dns.Msg, time.Duration, error) {
	if m.Responder == nil {
		return nil, 0, nil
	}
	return m.Responder(server, msg)
}
