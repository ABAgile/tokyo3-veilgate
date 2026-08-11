package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abagile/veilgate/internal/intercept"
)

func TestUpstreamTransportReusesHTTP2Connection(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "root.crt")
	keyPath := filepath.Join(dir, "root.key")
	if err := intercept.Generate(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	authority, err := intercept.Load(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := authority.TLSConfig("allowed.example")
	if err != nil {
		t.Fatal(err)
	}
	var connections atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("upstream protocol = %s", r.Proto)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	upstream.EnableHTTP2 = true
	upstream.TLS = serverTLS
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	upstream.StartTLS()
	defer upstream.Close()

	rootPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("append test root")
	}
	h := &Handler{
		UpstreamTLSConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
		},
	}
	defer h.Close()
	ip := netip.MustParseAddr("93.184.216.34")
	for range 3 {
		req, err := http.NewRequest(http.MethodGet, "https://allowed.example/data", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, _, err := h.roundTrip(req, ip, 443, "https")
		if err != nil {
			t.Fatal(err)
		}
		if resp.ProtoMajor != 2 {
			t.Fatalf("response protocol = %s", resp.Proto)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			t.Fatal(err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("upstream connections = %d, want 1", got)
	}
}

func TestUpstreamTransportTimesOutWaitingForResponseHeaders(t *testing.T) {
	h := &Handler{UpstreamResponseHeaderTimeout: 20 * time.Millisecond}
	defer h.Close()
	h.DialContext = func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			_, _ = http.ReadRequest(bufio.NewReader(server))
		}()
		return client, nil
	}
	request, err := http.NewRequest(http.MethodGet, "http://allowed.example/data", nil)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, _, err = h.roundTrip(request, netip.MustParseAddr("93.184.216.34"), 80, "http")
	if err == nil {
		t.Fatal("roundTrip unexpectedly succeeded")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("response-header timeout took %s", elapsed)
	}
}

func TestUpstreamTransportReusesHTTP1Connection(t *testing.T) {
	var connections atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	upstream.Start()
	defer upstream.Close()
	h := &Handler{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	}}
	defer h.Close()
	ip := netip.MustParseAddr("93.184.216.34")
	for range 3 {
		req, err := http.NewRequest(http.MethodGet, "http://allowed.example/data", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, _, err := h.roundTrip(req, ip, 80, "http")
		if err != nil {
			t.Fatal(err)
		}
		if resp.ProtoMajor != 1 {
			t.Fatalf("response protocol = %s", resp.Proto)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			t.Fatal(err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("upstream connections = %d, want 1", got)
	}
}

func TestUpstreamTransportCacheSeparatesPinnedIPs(t *testing.T) {
	h := &Handler{}
	defer h.Close()
	first := h.upstreamTransport("https", "api.example.com", netip.MustParseAddr("93.184.216.34"), 443)
	same := h.upstreamTransport("https", "api.example.com", netip.MustParseAddr("93.184.216.34"), 443)
	otherIP := h.upstreamTransport("https", "api.example.com", netip.MustParseAddr("93.184.216.35"), 443)
	otherHost := h.upstreamTransport("https", "other.example.com", netip.MustParseAddr("93.184.216.34"), 443)
	if first != same || first == otherIP || first == otherHost {
		t.Fatal("transport cache key does not preserve host/IP isolation")
	}
}

func TestUpstreamTransportRetainsEvictionsUntilClose(t *testing.T) {
	h := &Handler{}
	ip := netip.MustParseAddr("93.184.216.34")
	for port := 80; port <= 80+maxCachedUpstreamTransports; port++ {
		h.upstreamTransport("http", "api.example.com", ip, port)
	}
	if got := len(h.transports); got != maxCachedUpstreamTransports {
		t.Fatalf("cached transports = %d, want %d", got, maxCachedUpstreamTransports)
	}
	if got := len(h.drainingTransports); got != 1 {
		t.Fatalf("draining transports = %d, want 1", got)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUpstreamTransportRefusesAfterClose(t *testing.T) {
	h := &Handler{}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if got := h.upstreamTransport("http", "api.example.com", netip.MustParseAddr("93.184.216.34"), 80); got != nil {
		t.Fatal("transport was rebuilt after close")
	}
	request, err := http.NewRequest(http.MethodGet, "http://api.example.com/data", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.roundTrip(request, netip.MustParseAddr("93.184.216.34"), 80, "http"); err != errHandlerClosed {
		t.Fatalf("roundTrip error = %v, want %v", err, errHandlerClosed)
	}
}
