package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/alecthomas/kong"
	"github.com/jaxxstorm/dnstrace/internal/dnsclient"
	"github.com/jaxxstorm/dnstrace/internal/ladder"
	"github.com/jaxxstorm/dnstrace/internal/output"
	"github.com/jaxxstorm/dnstrace/internal/trace"
	"go.uber.org/zap"
)

var Version = "dev"

type CLI struct {
	Ladder LadderCmd `cmd:"" default:"withargs" help:"Resolver ladder trace (default)."`
	Trace  TraceCmd  `cmd:"trace" help:"Authoritative delegation trace (root -> TLD -> authoritative)."`
	Version VersionCmd `cmd:"version" help:"Print version."`
}

type LadderCmd struct {
	FQDN      string        `arg:"" name:"fqdn" help:"Fully qualified domain name."`
	RRType    string        `arg:"" name:"rrtype" enum:"A,AAAA,CNAME,TXT,MX,NS,SOA,SRV,PTR" optional:"" default:"A" help:"Record type to query."`
	DNSSEC    bool          `help:"Set the DNSSEC DO bit."`
	Transport string        `enum:"udp,tcp,auto" default:"auto" help:"Transport to use for queries."`
	MaxTime   time.Duration `default:"2s" help:"Time budget per resolver."`
	Output    string        `enum:"pretty,json" default:"pretty" help:"Output format."`
	Resolvers []string      `name:"resolver" help:"Resolver IPs to query (repeatable). If not set, uses system resolvers."`
	Verbose   bool          `help:"Enable verbose logging."`
	Debug     bool          `help:"Enable debug logging (includes raw DNS messages)."`
}

type TraceCmd struct {
	FQDN        string        `arg:"" name:"fqdn" help:"Fully qualified domain name."`
	RRType      string        `arg:"" name:"rrtype" enum:"A,AAAA,CNAME,TXT,MX,NS,SOA,SRV,PTR" optional:"" default:"A" help:"Record type to query."`
	DNSSEC      bool          `help:"Set the DNSSEC DO bit."`
	Transport   string        `enum:"udp,tcp,auto" default:"auto" help:"Transport to use for queries."`
	MaxTime     time.Duration `default:"2s" help:"Time budget per hop."`
	MaxHops     int           `default:"32" help:"Maximum delegation hops."`
	Parallelism int           `default:"6" help:"Parallelism per hop."`
	Output      string        `enum:"pretty,json" default:"pretty" help:"Output format."`
	Verbose     bool          `help:"Enable verbose logging."`
	Debug       bool          `help:"Enable debug logging (includes raw DNS messages)."`
}

type VersionCmd struct{}

func main() {
	cli := CLI{}
	ctx := kong.Parse(&cli,
		kong.Name("dnstrace"),
		kong.Description("Trace DNS delegation and explain resolution failures."),
	)

	if ctx.Selected() != nil && ctx.Selected().Name == "version" {
		fmt.Println(Version)
		return
	}

	if ctx.Command() == "trace <fqdn> [<rrtype>]" || ctx.Selected().Name == "trace" {
		logger, err := newLogger(cli.Trace.Verbose, cli.Trace.Debug)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		runAuthoritative(cli.Trace, logger)
		return
	}

	logger, err := newLogger(cli.Ladder.Verbose, cli.Ladder.Debug)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	runLadder(cli.Ladder, logger)
}

func runLadder(cmd LadderCmd, logger *zap.Logger) {
	mode := dnsclient.Mode(cmd.Transport)
	client := dnsclient.New(dnsclient.Options{
		DNSSEC:  cmd.DNSSEC,
		Mode:    mode,
		Timeout: cmd.MaxTime,
		Retries: 1,
		Logger:  logger,
	})

	resolvers := cmd.Resolvers
	if len(resolvers) == 0 {
		loaded, err := ladder.DefaultResolverChain()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		resolvers = loaded
	}

	ctx := context.Background()
	result, err := ladder.Trace(ctx, client, resolvers, cmd.FQDN, cmd.RRType, ladder.Config{Timeout: cmd.MaxTime, Logger: logger})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var rendered string
	if cmd.Output == "json" {
		rendered, err = output.RenderJSON(result)
	} else {
		rendered = output.RenderPretty(result)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println(rendered)
	if result.Diagnosis.Classification != "SUCCESS" {
		os.Exit(2)
	}
}

func runAuthoritative(cmd TraceCmd, logger *zap.Logger) {
	mode := dnsclient.Mode(cmd.Transport)
	client := dnsclient.New(dnsclient.Options{
		DNSSEC:  cmd.DNSSEC,
		Mode:    mode,
		Timeout: cmd.MaxTime,
		Retries: 1,
		Logger:  logger,
	})

	tracer := trace.NewTracer(client, trace.Config{
		MaxHops:     cmd.MaxHops,
		MaxTime:     cmd.MaxTime,
		Parallelism: cmd.Parallelism,
		Logger:      logger,
		Verbose:     cmd.Verbose || cmd.Debug,
	})

	ctx := context.Background()
	result, err := tracer.Trace(ctx, cmd.FQDN, cmd.RRType)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var rendered string
	if cmd.Output == "json" {
		rendered, err = output.RenderJSON(result)
	} else {
		rendered = output.RenderPretty(result)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println(rendered)
	if result.Diagnosis.Classification != "SUCCESS" {
		os.Exit(2)
	}
}

func newLogger(verbose bool, debug bool) (*zap.Logger, error) {
	if debug {
		cfg := zap.NewDevelopmentConfig()
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
		return cfg.Build()
	}
	cfg := zap.NewProductionConfig()
	if verbose {
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	} else {
		cfg.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	}
	return cfg.Build()
}
