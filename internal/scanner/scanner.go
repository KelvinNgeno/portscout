// Package scanner implements a concurrent TCP connect scanner.
package scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Port states reported in a Result.
const (
	StateOpen     = "open"
	StateClosed   = "closed"
	StateFiltered = "filtered"
	StateError    = "error"
)

// Result describes the outcome of probing one host:port pair.
type Result struct {
	Host      string  `json:"host"`
	IP        string  `json:"ip"`
	Port      int     `json:"port"`
	State     string  `json:"state"`
	Service   string  `json:"service,omitempty"`
	Banner    string  `json:"banner,omitempty"`
	LatencyMS float64 `json:"latency_ms,omitempty"`
}

// Config controls a scan.
type Config struct {
	Targets       []string      // hostnames or IPs (expand CIDRs first)
	Ports         []int         // ports to probe on every target
	Timeout       time.Duration // per-connection dial timeout
	Workers       int           // number of concurrent goroutines
	RateLimit     int           // max new connections per second; 0 = unlimited
	GrabBanner    bool          // read a banner / TLS info from open ports
	BannerTimeout time.Duration // how long to wait for a banner
	ShowAll       bool          // include closed/filtered results
}

// Scanner runs scans according to its Config.
type Scanner struct {
	cfg Config
}

// New validates cfg, applies defaults and returns a Scanner.
func New(cfg Config) (*Scanner, error) {
	if len(cfg.Targets) == 0 {
		return nil, errors.New("no targets")
	}
	if len(cfg.Ports) == 0 {
		return nil, errors.New("no ports")
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 100
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = time.Second
	}
	if cfg.BannerTimeout <= 0 {
		cfg.BannerTimeout = time.Second
	}
	return &Scanner{cfg: cfg}, nil
}

type target struct {
	name string // what the user typed
	ip   string // resolved address actually dialed
}

type job struct {
	t    target
	port int
}

// Scan probes every target/port pair and returns results sorted by host
// and port. If ctx is cancelled, the results gathered so far are returned
// together with ctx's error.
func (s *Scanner) Scan(ctx context.Context) ([]Result, error) {
	targets, err := resolveTargets(ctx, s.cfg.Targets)
	if err != nil {
		return nil, err
	}

	// Optional global rate limiter shared by all workers.
	var limiter <-chan time.Time
	if s.cfg.RateLimit > 0 {
		if interval := time.Second / time.Duration(s.cfg.RateLimit); interval > 0 {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			limiter = ticker.C
		}
	}

	jobs := make(chan job)
	results := make(chan Result)

	// Producer: feeds the job queue, stops early on cancellation.
	go func() {
		defer close(jobs)
		for _, t := range targets {
			for _, p := range s.cfg.Ports {
				select {
				case jobs <- job{t: t, port: p}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// Worker pool.
	var wg sync.WaitGroup
	for i := 0; i < s.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if limiter != nil {
					select {
					case <-limiter:
					case <-ctx.Done():
						return
					}
				}
				res := s.probe(ctx, j)
				select {
				case results <- res:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Close results once every worker has finished.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collector (runs in the calling goroutine).
	var out []Result
	for r := range results {
		if r.State == StateOpen || s.cfg.ShowAll {
			out = append(out, r)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})

	return out, ctx.Err()
}

// resolveTargets resolves each hostname once, up front, so we don't hit DNS
// for every single port.
func resolveTargets(ctx context.Context, hosts []string) ([]target, error) {
	out := make([]target, 0, len(hosts))
	for _, h := range hosts {
		if addr, err := netip.ParseAddr(h); err == nil {
			out = append(out, target{name: h, ip: addr.String()})
			continue
		}
		addrs, err := net.DefaultResolver.LookupHost(ctx, h)
		if err != nil || len(addrs) == 0 {
			return nil, fmt.Errorf("cannot resolve %q: %v", h, err)
		}
		out = append(out, target{name: h, ip: addrs[0]})
	}
	return out, nil
}

// probe attempts a single TCP connection and classifies the outcome.
func (s *Scanner) probe(ctx context.Context, j job) Result {
	res := Result{
		Host:    j.t.name,
		IP:      j.t.ip,
		Port:    j.port,
		Service: ServiceName(j.port),
	}

	addr := net.JoinHostPort(j.t.ip, strconv.Itoa(j.port))
	dialer := net.Dialer{Timeout: s.cfg.Timeout}

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		res.State = classify(err)
		return res
	}
	defer conn.Close()

	res.State = StateOpen
	res.LatencyMS = float64(time.Since(start).Microseconds()) / 1000.0

	if s.cfg.GrabBanner {
		res.Banner = grabBanner(conn, j.t.name, j.port, s.cfg.BannerTimeout)
	}
	return res
}

// classify maps a dial error to a port state.
//
//	refused  -> closed   (host answered with RST: nothing is listening)
//	anything else (timeout, unreachable) -> filtered: no answer, probably
//	dropped by a firewall
func classify(err error) string {
	if strings.Contains(strings.ToLower(err.Error()), "refused") {
		return StateClosed
	}
	return StateFiltered
}

// grabBanner collects whatever identifying text the service offers.
func grabBanner(conn net.Conn, host string, port int, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Services that speak TLS first: report protocol version and cert CN.
	if tlsPorts[port] {
		tc := tls.Client(conn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, //nolint:gosec // we are fingerprinting, not trusting
		})
		if err := tc.Handshake(); err != nil {
			return ""
		}
		state := tc.ConnectionState()
		info := "TLS " + tlsVersion(state.Version)
		if len(state.PeerCertificates) > 0 {
			if cn := state.PeerCertificates[0].Subject.CommonName; cn != "" {
				info += ", CN=" + cn
			}
		}
		return sanitize(info)
	}

	// HTTP servers stay silent until spoken to.
	if httpPorts[port] {
		_, _ = fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: portscout\r\n\r\n", host)
	}

	buf := make([]byte, 512)
	n, _ := conn.Read(buf) // a timeout here just means "no banner"
	if n == 0 {
		return ""
	}
	return cleanBanner(buf[:n])
}

// cleanBanner reduces raw bytes to one printable line. For HTTP responses
// it appends the Server header, which is usually the interesting part.
func cleanBanner(b []byte) string {
	lines := strings.Split(string(b), "\n")
	first := strings.TrimSpace(lines[0])

	if strings.HasPrefix(first, "HTTP/") {
		for _, l := range lines[1:] {
			if strings.HasPrefix(strings.ToLower(l), "server:") {
				first += " | " + strings.TrimSpace(l)
				break
			}
		}
	}
	return sanitize(first)
}

// sanitize drops non-printable characters (banners are attacker-controlled
// data and must never be able to inject terminal escape sequences) and caps
// the length.
func sanitize(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if unicode.IsPrint(r) {
			sb.WriteRune(r)
		}
	}
	out := sb.String()
	if len(out) > 120 {
		out = out[:120] + "..."
	}
	return out
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
