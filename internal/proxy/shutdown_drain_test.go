package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SatriaBagusNurhadianto/7guard/internal/config"
)

// TestGracefulShutdownDrain verifies that an in-flight request to a slow
// upstream completes when Shutdown is invoked, instead of being dropped.
// Harness scaffold provided by @astra-ox-github; assertions/tuning by @viola.
func TestGracefulShutdownDrain(t *testing.T) {
	// Slow upstream: holds the response for 2s so the proxy request stays
	// in-flight when Shutdown is called.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.RulesDir = "../../rules"
	cfg.Upstream = upstream.URL
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.Profile = config.ProfileLite
	cfg.Mode = config.ModeDetect
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config.Validate: %v", err)
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	// Mirror Run() but bind to an OS-assigned port so we know where to dial.
	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleRequest)
	mux.HandleFunc("/health", srv.handleHealth)
	httpSrv := &http.Server{Handler: mux, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second}
	srv.httpSrv = httpSrv

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			t.Logf("serve: %v", err)
		}
	}()

	baseURL := fmt.Sprintf("http://%s", ln.Addr().String())

	// Wait for the server to be ready.
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get(baseURL + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not become ready")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Issue a slow request in the background.
	reqDone := make(chan struct {
		code int
		err  error
	}, 1)
	go func() {
		resp, err := http.Get(baseURL + "/")
		code := 0
		if resp != nil {
			code = resp.StatusCode
			resp.Body.Close()
		}
		reqDone <- struct {
			code int
			err  error
		}{code: code, err: err}
	}()

	// Give the request time to reach the upstream and block.
	time.Sleep(1500 * time.Millisecond)

	// Trigger graceful shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown returned error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 6*time.Second {
		t.Fatalf("Shutdown took too long: %v", elapsed)
	}

	// The in-flight request must have completed (drained), not been cut off.
	select {
	case r := <-reqDone:
		if r.err != nil {
			t.Fatalf("in-flight request errored: %v", r.err)
		}
		if r.code != http.StatusOK {
			t.Fatalf("in-flight request got status %d, want 200 (drained)", r.code)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("in-flight request did not complete after Shutdown")
	}
}
