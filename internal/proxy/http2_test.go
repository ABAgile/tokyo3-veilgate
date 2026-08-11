package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/abagile/veilgate/internal/config"
	"github.com/abagile/veilgate/internal/flow"
	"github.com/abagile/veilgate/internal/intercept"
)

func TestInterceptedHTTP2MaxConcurrentStreams(t *testing.T) {
	for _, test := range []struct {
		name  string
		limit int64
		want  uint32
	}{
		{name: "default mediation limit", want: 32},
		{name: "small limit is capped", limit: 1, want: 64},
		{name: "four megabytes", limit: 4 << 20, want: 32},
		{name: "eight megabytes", limit: 8 << 20, want: 16},
		{name: "maximum configured limit", limit: 64 << 20, want: 2},
		{name: "oversized limit remains one", limit: 128 << 20, want: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := &Handler{MediationLimit: test.limit}
			if got := h.interceptedHTTP2MaxConcurrentStreams(); got != test.want {
				t.Fatalf("interceptedHTTP2MaxConcurrentStreams() = %d, want %d", got, test.want)
			}
		})
	}
}

func testHTTP2Authority(t *testing.T) (*intercept.Authority, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "intercept.crt")
	keyPath := filepath.Join(dir, "intercept.key")
	if err := intercept.Generate(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	authority, err := intercept.Load(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("append interception root")
	}
	return authority, roots
}

func testHTTP2Identity() *config.Client {
	return &config.Client{Name: "agent", AllowedHosts: []string{"allowed.example"}, AllowedPorts: []int{443}}
}

func newInterceptedHTTP2Client(t *testing.T, h *Handler, authority *intercept.Authority, outer *http.Request, identity *config.Client, host string, port int) (*http2.Transport, func()) {
	t.Helper()
	serverConfig, err := authority.TLSConfig(host)
	if err != nil {
		t.Fatal(err)
	}
	serverConn, clientConn := net.Pipe()
	serverTLS := tls.Server(serverConn, serverConfig)
	serverDone := make(chan error, 1)
	go func() {
		defer serverTLS.Close()
		if err := serverTLS.Handshake(); err != nil {
			serverDone <- err
			return
		}
		_, _, _, reason := h.interceptHTTP2(serverTLS, outer, identity, host, port, "test-session")
		if reason != "" {
			serverDone <- errors.New(reason)
			return
		}
		serverDone <- nil
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, ServerName: host, NextProtos: []string{"h2"}}) // #nosec G402 -- test certificate is generated locally.
	transport := &http2.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			if err := clientTLS.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			return clientTLS, nil
		},
	}
	finish := func() {
		_ = clientTLS.Close()
		select {
		case err := <-serverDone:
			if err != nil {
				t.Errorf("interceptHTTP2 session: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("interceptHTTP2 session did not stop")
		}
	}
	return transport, finish
}

func TestInterceptedHTTP2MediatesStreamingResponseAndTrailers(t *testing.T) {
	authority, roots := testHTTP2Authority(t)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Trailer", "X-Secret-Trailer")
		_, _ = io.WriteString(w, "data: real-api-key\\n\\n")
		w.Header().Set("X-Secret-Trailer", "real-api-key")
	}))
	upstream.TLS, _ = authority.TLSConfig("allowed.example")
	upstream.StartTLS()
	defer upstream.Close()

	recorded := make(chan flow.Flow, 1)
	h := &Handler{
		Resolver: fixedResolver{netip.MustParseAddr("93.184.216.34")}, Secrets: proxyTestBroker(t),
		CaptureLimit: 4096, MediationLimit: 4096,
		UpstreamTLSConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
		},
		Record: func(_ context.Context, item flow.Flow) { recorded <- item },
	}
	defer h.Close()
	outer := httptest.NewRequest(http.MethodConnect, "https://allowed.example:443", nil)
	client, finish := newInterceptedHTTP2Client(t, h, authority, outer, testHTTP2Identity(), "allowed.example", 443)
	request := httptest.NewRequest(http.MethodGet, "https://allowed.example/stream", nil)
	response, err := client.RoundTrip(request)
	if err != nil {
		finish()
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		finish()
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "data: "+testPlaceholder+"\\n\\n" || response.Trailer.Get("X-Secret-Trailer") != testPlaceholder {
		finish()
		t.Fatalf("response = %d body = %q trailer = %#v", response.StatusCode, body, response.Trailer)
	}
	finish()
	select {
	case item := <-recorded:
		if item.Mode != "intercepted-h2" || item.Status != http.StatusOK || item.Capture.ResponseBody == nil || item.Capture.ResponseBody.Text != "data: [secret:api_key]\\n\\n" || len(item.ResponseSecretNames) != 1 || item.ResponseSecretNames[0] != "api_key" {
			t.Fatalf("recorded flow = %#v", item)
		}
	case <-time.After(time.Second):
		t.Fatal("intercepted HTTP/2 flow was not recorded")
	}
}

func TestInterceptedHTTP2RecordsStreamingDecodeFailure(t *testing.T) {
	authority, roots := testHTTP2Authority(t)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write([]byte{0x1f, 0x8b, 0x08})
	}))
	upstream.TLS, _ = authority.TLSConfig("allowed.example")
	upstream.StartTLS()
	defer upstream.Close()

	recorded := make(chan flow.Flow, 1)
	h := &Handler{
		Resolver: fixedResolver{netip.MustParseAddr("93.184.216.216")}, CaptureLimit: 4096, MediationLimit: 4096,
		UpstreamTLSConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
		},
		Record: func(_ context.Context, item flow.Flow) { recorded <- item },
	}
	defer h.Close()
	outer := httptest.NewRequest(http.MethodConnect, "https://allowed.example:443", nil)
	client, finish := newInterceptedHTTP2Client(t, h, authority, outer, testHTTP2Identity(), "allowed.example", 443)
	request := httptest.NewRequest(http.MethodGet, "https://allowed.example/truncated", nil)
	response, err := client.RoundTrip(request)
	if err != nil {
		finish()
		t.Fatal(err)
	}
	_, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		finish()
		t.Fatalf("response status = %d", response.StatusCode)
	}
	finish()
	select {
	case item := <-recorded:
		if item.Status != http.StatusOK || !strings.Contains(item.Reason, "decode gzip stream") {
			t.Fatalf("recorded flow = %#v", item)
		}
	case <-time.After(time.Second):
		t.Fatal("streaming-error HTTP/2 flow was not recorded")
	}
}

func TestInterceptedHTTP2RejectsRequestMediationFailure(t *testing.T) {
	authority, _ := testHTTP2Authority(t)
	recorded := make(chan flow.Flow, 1)
	h := &Handler{
		Resolver: fixedResolver{netip.MustParseAddr("93.184.216.34")}, Secrets: proxyTestBroker(t),
		CaptureLimit: 4096, MediationLimit: 4096,
		Record: func(_ context.Context, item flow.Flow) { recorded <- item },
	}
	defer h.Close()
	outer := httptest.NewRequest(http.MethodConnect, "https://allowed.example:443", nil)
	client, finish := newInterceptedHTTP2Client(t, h, authority, outer, testHTTP2Identity(), "allowed.example", 443)
	request := httptest.NewRequest(http.MethodPost, "https://allowed.example/invalid", strings.NewReader("{"))
	request.Header.Set("Content-Type", "application/json")
	response, err := client.RoundTrip(request)
	if err != nil {
		finish()
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "malformed") {
		finish()
		t.Fatalf("response = %d body = %q", response.StatusCode, body)
	}
	finish()
	select {
	case item := <-recorded:
		if item.Decision != "denied" || item.Status != http.StatusForbidden || !strings.Contains(item.Reason, "malformed") {
			t.Fatalf("recorded flow = %#v", item)
		}
	case <-time.After(time.Second):
		t.Fatal("failed HTTP/2 flow was not recorded")
	}
}

func TestInterceptedHTTP2RejectsMisdirectedRequest(t *testing.T) {
	authority, _ := testHTTP2Authority(t)
	h := &Handler{Resolver: fixedResolver{netip.MustParseAddr("93.184.216.34")}}
	defer h.Close()
	outer := httptest.NewRequest(http.MethodConnect, "https://allowed.example:443", nil)
	client, finish := newInterceptedHTTP2Client(t, h, authority, outer, testHTTP2Identity(), "allowed.example", 443)
	request := httptest.NewRequest(http.MethodGet, "https://allowed.example/misdirected", nil)
	request.Host = "other.example"
	response, err := client.RoundTrip(request)
	if err != nil {
		finish()
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusMisdirectedRequest {
		finish()
		t.Fatalf("response status = %d", response.StatusCode)
	}
	finish()
}
