// Command portscout is a fast, concurrent TCP port scanner.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/kelvinngeno/portscout/internal/output"
	"github.com/kelvinngeno/portscout/internal/scanner"
)

// version is overridden at build time: -ldflags "-X main.version=v1.0.0"
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("portscout", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		ports       = fs.String("p", "top", `ports: "80", "1-1024", "22,80,443", "top" or "all"`)
		timeout     = fs.Duration("timeout", 800*time.Millisecond, "connection timeout per port")
		workers     = fs.Int("workers", 200, "number of concurrent workers")
		rate        = fs.Int("rate", 0, "max new connections per second (0 = unlimited)")
		banner      = fs.Bool("banner", true, "grab service banners / TLS info from open ports")
		showAll     = fs.Bool("all", false, "also show closed and filtered ports")
		format      = fs.String("format", "table", "output format: "+strings.Join(output.Formats, ", "))
		outFile     = fs.String("o", "", "write results to this file instead of stdout")
		showVersion = fs.Bool("version", false, "print version and exit")
	)

	fs.Usage = func() {
		fmt.Fprintf(stderr, `portscout %s - concurrent TCP port scanner

Usage:
  portscout [flags] <target> [target...]

Targets can be hostnames, IP addresses or CIDR blocks (up to /16).

Flags:
`, version)
		fs.PrintDefaults()
		fmt.Fprint(stderr, `
Examples:
  portscout scanme.nmap.org
  portscout -p 1-1024 -format json 192.168.1.10
  portscout -p 22,80,443 -rate 100 10.0.0.0/24

Only scan systems you own or have explicit permission to test.
`)
	}

	targets, err := parseArgs(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *showVersion {
		fmt.Fprintln(stdout, "portscout", version)
		return 0
	}
	if len(targets) == 0 {
		fs.Usage()
		return 2
	}

	portList, err := scanner.ParsePorts(*ports)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	hosts, err := scanner.ExpandTargets(targets)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}

	s, err := scanner.New(scanner.Config{
		Targets:    hosts,
		Ports:      portList,
		Timeout:    *timeout,
		Workers:    *workers,
		RateLimit:  *rate,
		GrabBanner: *banner,
		ShowAll:    *showAll,
	})
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}

	// Ctrl+C cancels the scan but still prints what was found so far.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Fprintf(stderr, "Scanning %d host(s) x %d port(s) with %d workers...\n",
		len(hosts), len(portList), *workers)
	start := time.Now()

	results, scanErr := s.Scan(ctx)
	interrupted := errors.Is(scanErr, context.Canceled)
	if scanErr != nil && !interrupted {
		fmt.Fprintln(stderr, "error:", scanErr)
		return 1
	}

	dst := stdout
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		defer f.Close()
		dst = f
	}

	if err := output.Write(dst, *format, results); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}

	if interrupted {
		fmt.Fprintln(stderr, "Interrupted: results above are partial.")
		return 130
	}
	fmt.Fprintf(stderr, "Done in %s.\n", time.Since(start).Round(time.Millisecond))
	return 0
}

// parseArgs lets flags appear before, between or after targets
// (Go's flag package normally stops at the first non-flag argument).
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var targets []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return targets, nil
		}
		targets = append(targets, rest[0])
		args = rest[1:]
	}
}
