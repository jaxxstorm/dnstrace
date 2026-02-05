package dnsclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type Mode string

const (
	ModeUDP  Mode = "udp"
	ModeTCP  Mode = "tcp"
	ModeAuto Mode = "auto"
)

type Options struct {
	DNSSEC    bool
	Mode      Mode
	Timeout   time.Duration
	Retries   int
	EDNS0Size uint16
	Logger    *zap.Logger
}

type Client struct {
	opts Options
	udp  Transport
	tcp  Transport
}

func New(opts Options) *Client {
	return NewWithTransports(opts, &udpTransport{timeout: opts.Timeout}, &tcpTransport{timeout: opts.Timeout})
}

func NewWithTransports(opts Options, udp Transport, tcp Transport) *Client {
	if opts.Timeout == 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.Retries == 0 {
		opts.Retries = 1
	}
	if opts.EDNS0Size == 0 {
		opts.EDNS0Size = 1232
	}
	if opts.Mode == "" {
		opts.Mode = ModeAuto
	}
	if opts.Logger == nil {
		opts.Logger = zap.NewNop()
	}
	return &Client{
		opts: opts,
		udp:  udp,
		tcp:  tcp,
	}
}

func (c *Client) BuildQuery(name string, qtype uint16) *dns.Msg {
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = false
	msg.SetEdns0(c.opts.EDNS0Size, c.opts.DNSSEC)
	return msg
}

func (c *Client) Exchange(ctx context.Context, server string, msg *dns.Msg) (*dns.Msg, time.Duration, string, error) {
	server = NormalizeServer(server)
	switch c.opts.Mode {
	case ModeTCP:
		resp, rtt, err := c.exchangeWithRetries(ctx, c.tcp, server, msg, "tcp")
		return resp, rtt, "tcp", err
	case ModeUDP:
		resp, rtt, err := c.exchangeWithRetries(ctx, c.udp, server, msg, "udp")
		return resp, rtt, "udp", err
	case ModeAuto:
		resp, rtt, err := c.exchangeWithRetries(ctx, c.udp, server, msg, "udp")
		if err == nil && resp != nil && resp.Truncated {
			c.opts.Logger.Debug("udp truncated, retrying with tcp", zap.String("server", server))
			resp, rtt, err = c.exchangeWithRetries(ctx, c.tcp, server, msg, "tcp")
			return resp, rtt, "tcp", err
		}
		return resp, rtt, "udp", err
	default:
		return nil, 0, "", fmt.Errorf("unsupported transport mode: %s", c.opts.Mode)
	}
}

func (c *Client) exchangeWithRetries(ctx context.Context, transport Transport, server string, msg *dns.Msg, mode string) (*dns.Msg, time.Duration, error) {
	var lastErr error
	for i := 0; i < c.opts.Retries; i++ {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		resp, rtt, err := transport.Exchange(ctx, server, msg.Copy())
		if err == nil {
			c.logRaw(mode, server, msg, resp)
			return resp, rtt, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("dns exchange failed")
	}
	return nil, 0, lastErr
}

func (c *Client) logRaw(mode, server string, req, resp *dns.Msg) {
	if c.opts.Logger.Core().Enabled(zap.DebugLevel) {
		c.opts.Logger.Debug("dns request",
			zap.String("transport", mode),
			zap.String("server", server),
			zap.String("message", req.String()),
		)
		if resp != nil {
			c.opts.Logger.Debug("dns response",
				zap.String("transport", mode),
				zap.String("server", server),
				zap.String("message", resp.String()),
			)
		}
	}
}

func NormalizeServer(server string) string {
	if server == "" {
		return server
	}
	if strings.HasPrefix(server, "[") {
		if strings.Contains(server, "]:") {
			return server
		}
		return server + ":53"
	}
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	if strings.Contains(server, ":") {
		return "[" + server + "]:53"
	}
	return server + ":53"
}
