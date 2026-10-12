package scanner

import (
	"context"
	"net"
	"testing"
	"time"
)

// startListener opens a TCP listener on a free local port. If banner is
// non-empty, it is written to every client that connects.
func startListener(t *testing.T, banner string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if banner != "" {
				_, _ = conn.Write([]byte(banner))
			}
			conn.Close()
		}
	}()

	return ln.Addr().(*net.TCPAddr).Port
}

// freePort returns a port that was free a moment ago (so: closed).
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func TestScanFindsOpenAndClosed(t *testing.T) {
	open := startListener(t, "")
	closed := freePort(t)

	s, err := New(Config{
		Targets: []string{"127.0.0.1"},
		Ports:   []int{open, closed},
		Timeout: 500 * time.Millisecond,
		Workers: 4,
		ShowAll: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	results, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2: %+v", len(results), results)
	}

	states := map[int]string{}
	for _, r := range results {
		states[r.Port] = r.State
	}
	if states[open] != StateOpen {
		t.Errorf("port %d state = %q, want open", open, states[open])
	}
	if states[closed] != StateClosed {
		t.Errorf("port %d state = %q, want closed", closed, states[closed])
	}
}

func TestScanHidesClosedByDefault(t *testing.T) {
	open := startListener(t, "")
	closed := freePort(t)

	s, _ := New(Config{
		Targets: []string{"127.0.0.1"},
		Ports:   []int{open, closed},
		Timeout: 500 * time.Millisecond,
	})
	results, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Port != open {
		t.Fatalf("expected only the open port, got %+v", results)
	}
}

func TestBannerGrab(t *testing.T) {
	port := startListener(t, "SSH-2.0-TestServer_1.0\r\n")

	s, _ := New(Config{
		Targets:       []string{"127.0.0.1"},
		Ports:         []int{port},
		Timeout:       500 * time.Millisecond,
		GrabBanner:    true,
		BannerTimeout: 500 * time.Millisecond,
	})
	results, err := s.Scan(context.Background())
	if err != nil || len(results) != 1 {
		t.Fatalf("results %+v, err %v", results, err)
	}
	if got, want := results[0].Banner, "SSH-2.0-TestServer_1.0"; got != want {
		t.Errorf("banner = %q, want %q", got, want)
	}
}

func TestRateLimitSlowsScan(t *testing.T) {
	open := startListener(t, "")
	ports := make([]int, 0, 5)
	for i := 0; i < 5; i++ {
		ports = append(ports, open)
	}

	s, _ := New(Config{
		Targets:   []string{"127.0.0.1"},
		Ports:     ports,
		Timeout:   500 * time.Millisecond,
		RateLimit: 10, // 5 probes at 10/s should take roughly 400ms+
	})

	start := time.Now()
	if _, err := s.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 300*time.Millisecond {
		t.Errorf("scan finished in %s; rate limit does not appear to apply", elapsed)
	}
}

func TestCancellationReturnsPromptly(t *testing.T) {
	ports := make([]int, 0, 2000)
	for p := 20000; p < 22000; p++ {
		ports = append(ports, p)
	}
	s, _ := New(Config{
		Targets:   []string{"127.0.0.1"},
		Ports:     ports,
		Timeout:   time.Second,
		Workers:   2,
		RateLimit: 5, // deliberately slow so cancellation matters
	})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { _, err := s.Scan(ctx); done <- err }()

	select {
	case err := <-done:
		if err == nil {
			t.Error("expected a context error after cancellation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Scan did not return after context cancellation")
	}
}

func TestSanitizeStripsControlChars(t *testing.T) {
	got := sanitize("hello\x1b[31mred\x00world")
	if got != "hello[31mredworld" {
		t.Errorf("sanitize = %q", got)
	}
}

func TestCleanBannerHTTP(t *testing.T) {
	raw := []byte("HTTP/1.0 200 OK\r\nDate: x\r\nServer: nginx/1.25\r\n\r\n")
	got := cleanBanner(raw)
	if got != "HTTP/1.0 200 OK | Server: nginx/1.25" {
		t.Errorf("cleanBanner = %q", got)
	}
}

func TestServiceName(t *testing.T) {
	if ServiceName(22) != "ssh" || ServiceName(65000) != "unknown" {
		t.Error("unexpected service names")
	}
}
