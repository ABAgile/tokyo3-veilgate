package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abagile/veilgate/internal/config"
	"github.com/abagile/veilgate/internal/flow"
	"github.com/abagile/veilgate/internal/intercept"
)

func inspectPolicy(t *testing.T, client config.Client) *config.File {
	t.Helper()
	client.Name, client.Token = "agent", "012345678901234567890123"
	if client.AllowedHosts == nil {
		client.AllowedHosts = []string{"allowed.example"}
	}
	client.AllowedPorts = []int{443}
	policy := &config.File{Clients: []config.Client{client}}
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestHandlingForInspectHostsAndRules(t *testing.T) {
	h := &Handler{}
	for _, test := range []struct {
		name   string
		client config.Client
		host   string
		want   handling
	}{
		{"all mode defaults to full", config.Client{}, "allowed.example", handlingFull},
		{"all mode inspect host", config.Client{InspectHosts: []string{"allowed.example"}}, "allowed.example", handlingInspect},
		{"listed mode defaults to opaque", config.Client{InterceptMode: config.ModeOpaque}, "allowed.example", handlingOpaque},
		{"listed mode inspect host", config.Client{InterceptMode: config.ModeOpaque, InspectHosts: []string{"*.example"}}, "allowed.example", handlingInspect},
		{"intercept host beats inspect", config.Client{InterceptMode: config.ModeOpaque, InterceptHosts: []string{"allowed.example"}, InspectHosts: []string{"allowed.example"}}, "allowed.example", handlingFull},
		{"opaque beats inspect", config.Client{OpaqueHosts: []string{"allowed.example"}, InspectHosts: []string{"allowed.example"}}, "allowed.example", handlingOpaque},
		{"rules force inspection of an opaque host", config.Client{OpaqueHosts: []string{"allowed.example"}, AllowedRules: []config.Rule{{Host: "allowed.example", Methods: []string{"GET"}}}}, "allowed.example", handlingInspect},
		{"rules force inspection in listed mode", config.Client{InterceptMode: config.ModeOpaque, AllowedRules: []config.Rule{{Host: "allowed.example", Methods: []string{"GET"}}}}, "allowed.example", handlingInspect},
		{"inspect mode defaults to inspect", config.Client{InterceptMode: config.ModeInspect}, "allowed.example", handlingInspect},
		{"inspect mode intercept host is full", config.Client{InterceptMode: config.ModeInspect, InterceptHosts: []string{"allowed.example"}}, "allowed.example", handlingFull},
		{"inspect mode opaque host is opaque", config.Client{InterceptMode: config.ModeInspect, OpaqueHosts: []string{"allowed.example"}}, "allowed.example", handlingOpaque},
		{"rules in all mode keep full mediation", config.Client{AllowedRules: []config.Rule{{Host: "allowed.example", Methods: []string{"GET"}}}}, "allowed.example", handlingFull},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &inspectPolicy(t, test.client).Clients[0]
			if got := h.handlingFor(client, test.host); got != test.want {
				t.Fatalf("handlingFor() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRequestRulePath(t *testing.T) {
	for _, test := range []struct {
		raw     string
		want    string
		wantErr bool
	}{
		{raw: "/bucket/a%20b.zip", want: "/bucket/a b.zip"},
		{raw: "/bucket/a:b@v1.zip", want: "/bucket/a:b@v1.zip"},
		{raw: "/bucket/../other", wantErr: true},
		{raw: "/bucket/%2e%2e/other", wantErr: true},
		{raw: "/bucket/./x", wantErr: true},
		{raw: "/bucket%2Fx", wantErr: true},
		{raw: "/bucket%5cx", wantErr: true},
		{raw: "/bucket/%252e%252e/x", wantErr: true},
		{raw: "/bucket/%00", wantErr: true},
	} {
		u, err := url.Parse("https://allowed.example" + test.raw)
		if err != nil {
			t.Fatalf("parse %q: %v", test.raw, err)
		}
		got, err := requestRulePath(u)
		if (err != nil) != test.wantErr || got != test.want {
			t.Errorf("requestRulePath(%q) = %q, %v", test.raw, got, err)
		}
	}
	if _, err := requestRulePath(&url.URL{Path: "*"}); err == nil {
		t.Error("requestRulePath accepted a non-absolute path")
	}
}

func TestLimitedBody(t *testing.T) {
	read := func(limit int64, input string) (string, error) {
		body := &limitedBody{ReadCloser: io.NopCloser(strings.NewReader(input)), remaining: limit}
		data, err := io.ReadAll(body)
		return string(data), err
	}
	if data, err := read(5, "12345"); err != nil || data != "12345" {
		t.Fatalf("at limit = %q, %v", data, err)
	}
	if data, err := read(5, "123456"); err == nil || len(data) > 5 {
		t.Fatalf("over limit = %q, %v", data, err)
	}
}

var inspectLarge = strings.Repeat("x", 4096)

type inspectEnv struct {
	do        func(method, path string, body io.Reader, header http.Header) (int, string)
	store     *flow.Store
	hits      *atomic.Int32
	closeIdle func()
	transport *http.Transport
}

// newInspectEnv starts an interception proxy with a 64-byte mediation limit in
// front of an HTTPS upstream. GET and HEAD return inspectLarge; PUT echoes the
// number of bytes received.
func newInspectEnv(t *testing.T, policy *config.File, protocol string) *inspectEnv {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := intercept.Generate(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	authority, err := intercept.Load(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(rootPEM)
	upstreamTLS, err := authority.TLSConfig("allowed.example")
	if err != nil {
		t.Fatal(err)
	}
	env := &inspectEnv{store: flow.NewStore(32), hits: new(atomic.Int32)}
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.hits.Add(1)
		if r.URL.Path == "/unknown-length" {
			// Flushing before the handler returns leaves an HTTP/2 response
			// without a Content-Length.
			_, _ = io.WriteString(w, inspectLarge[:2048])
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, inspectLarge[2048:])
			return
		}
		if r.Method == http.MethodPut || r.Method == http.MethodPost {
			n, _ := io.Copy(io.Discard, r.Body)
			_, _ = io.WriteString(w, strings.Repeat("u", int(n)))
			return
		}
		_, _ = io.WriteString(w, inspectLarge)
	}))
	upstream.EnableHTTP2 = true
	upstream.TLS = upstreamTLS
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	h := &Handler{
		Policy: policy, Resolver: fixedResolver{netip.MustParseAddr("93.184.216.34")},
		Store: env.store, Interceptor: authority, MediationLimit: 64,
		UpstreamTLSConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
		},
	}
	proxyServer := httptest.NewServer(h)
	t.Cleanup(proxyServer.Close)
	proxyURL, _ := url.Parse(proxyServer.URL)
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true, ForceAttemptHTTP2: protocol == "h2",
		ProxyConnectHeader: http.Header{"Proxy-Authorization": {"Bearer 012345678901234567890123"}},
		TLSClientConfig:    &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	env.closeIdle = transport.CloseIdleConnections
	env.transport = transport
	env.do = func(method, path string, body io.Reader, header http.Header) (int, string) {
		t.Helper()
		request, err := http.NewRequest(method, "https://allowed.example"+path, body)
		if err != nil {
			t.Fatal(err)
		}
		maps.Copy(request.Header, header)
		response, err := client.Do(request)
		if err != nil {
			return 0, err.Error()
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(data)
	}
	return env
}

func TestInspectProxyStreamsBodiesAndEnforcesRules(t *testing.T) {
	policy := inspectPolicy(t, config.Client{
		InterceptMode: config.ModeOpaque,
		InspectHosts:  []string{"allowed.example"},
		AllowedRules: []config.Rule{
			{Host: "allowed.example", Methods: []string{"GET", "head"}, PathPrefixes: []string{"/bucket", "/other/data/"}},
			{Host: "allowed.example", Methods: []string{"PUT"}, PathPrefixes: []string{"/upload/"}, MaxRequestBytes: 10},
		},
	})
	large := inspectLarge
	for _, protocol := range []string{"h2", "http/1.1"} {
		t.Run(protocol, func(t *testing.T) {
			env := newInspectEnv(t, policy, protocol)
			do, store, upstreamHits := env.do, env.store, env.hits

			if status, body := do(http.MethodGet, "/bucket/obj.zip", nil, nil); status != http.StatusOK || body != large {
				t.Fatalf("allowed GET = %d, %d bytes (want streamed body beyond the mediation limit)", status, len(body))
			}
			if status, body := do(http.MethodGet, "/other/data/x", nil, nil); status != http.StatusOK || body != large {
				t.Fatalf("second prefix GET = %d, %d bytes", status, len(body))
			}
			before := upstreamHits.Load()
			for name, test := range map[string]struct {
				method, path string
				header       http.Header
			}{
				"method not permitted":    {http.MethodPost, "/bucket/obj", nil},
				"unlisted path":           {http.MethodGet, "/other/x", nil},
				"prefix boundary":         {http.MethodGet, "/bucketeer/x", nil},
				"dot segments":            {http.MethodGet, "/bucket/%2e%2e/other/x", nil},
				"encoded separator":       {http.MethodGet, "/bucket%2f..%2fother", nil},
				"method override header":  {http.MethodGet, "/bucket/obj", http.Header{"X-Http-Method-Override": {"DELETE"}}},
				"put outside its prefix":  {http.MethodPut, "/bucket/obj", nil},
				"get on the upload path":  {http.MethodGet, "/upload/x", nil},
				"wrong host path casing":  {http.MethodGet, "/Bucket/obj", nil},
				"put with overlong body":  {http.MethodPut, "/upload/x", http.Header{}},
				"get after rejected puts": {http.MethodGet, "/", nil},
			} {
				var body io.Reader
				if test.method == http.MethodPut {
					body = strings.NewReader(strings.Repeat("p", 50))
				}
				status, text := do(test.method, test.path, body, test.header)
				wantStatus := http.StatusForbidden
				if name == "put with overlong body" {
					wantStatus = http.StatusRequestEntityTooLarge
				}
				if status != wantStatus {
					t.Errorf("%s: status = %d (%s), want %d", name, status, text, wantStatus)
				}
			}
			if upstreamHits.Load() != before {
				t.Errorf("denied requests reached upstream (%d hits)", upstreamHits.Load()-before)
			}

			if status, body := do(http.MethodPut, "/upload/x", strings.NewReader("12345"), nil); status != http.StatusOK || body != "uuuuu" {
				t.Fatalf("PUT within cap = %d %q", status, body)
			}
			// An upload of unknown length must be cut off at the cap.
			if status, _ := do(http.MethodPut, "/upload/x", io.NopCloser(strings.NewReader(strings.Repeat("p", 500))), nil); status == http.StatusOK {
				t.Fatal("chunked PUT over max_request_bytes succeeded")
			}
			env.closeIdle()

			var streamed *flow.Flow
			deadline := time.Now().Add(time.Second)
			for streamed == nil && time.Now().Before(deadline) {
				for _, item := range storedFlows(t, store, 1) {
					if item.Method == http.MethodGet && item.Path == "/bucket/obj.zip" {
						copy := item
						streamed = &copy
					}
				}
				time.Sleep(time.Millisecond)
			}
			if streamed == nil {
				t.Fatal("inspected flow was not recorded")
			}
			wantMode := "inspected-h2"
			if protocol != "h2" {
				wantMode = "inspected"
			}
			if streamed.Mode != wantMode || streamed.Decision != "allowed" || streamed.Status != http.StatusOK || streamed.BytesReceived != int64(len(large)) {
				t.Fatalf("inspected flow = %#v", streamed)
			}
			if streamed.Capture.ResponseBody != nil || streamed.Capture.RequestBody != nil || streamed.Capture.ResponseHeaders == nil {
				t.Fatalf("capture = %#v, want headers only", streamed.Capture)
			}
		})
	}
}

func TestConnectRequiresInterceptionForRules(t *testing.T) {
	policy := inspectPolicy(t, config.Client{
		OpaqueHosts:  []string{"allowed.example"},
		AllowedRules: []config.Rule{{Host: "allowed.example", Methods: []string{"GET"}}},
	})
	h := &Handler{Policy: policy, Resolver: fixedResolver{netip.MustParseAddr("93.184.216.34")}}
	defer h.Close()
	request := httptest.NewRequest(http.MethodConnect, "allowed.example:443", nil)
	request.Header.Set("Proxy-Authorization", "Bearer 012345678901234567890123")
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "allowed_rules") {
		t.Fatalf("response = %d %q, want 503 requiring interception", recorder.Code, recorder.Body.String())
	}
}

func TestInspectHostDefaultsToReadOnly(t *testing.T) {
	policy := inspectPolicy(t, config.Client{
		InterceptMode: config.ModeOpaque,
		InspectHosts:  []string{"allowed.example"},
	})
	// An explicit rule replaces the default; a "/" prefix is the escape hatch
	// that permits any method and path.
	open := inspectPolicy(t, config.Client{
		InterceptMode: config.ModeOpaque,
		InspectHosts:  []string{"allowed.example"},
		AllowedRules:  []config.Rule{{Host: "allowed.example", PathPrefixes: []string{"/"}}},
	})
	t.Run("explicit rule replaces default", func(t *testing.T) {
		env := newInspectEnv(t, open, "h2")
		if status, body := env.do(http.MethodPost, "/x", strings.NewReader("data"), nil); status != http.StatusOK || body != "uuuu" {
			t.Fatalf("POST under explicit rule = %d %q", status, body)
		}
		env.closeIdle()
	})
	for _, protocol := range []string{"h2", "http/1.1"} {
		t.Run(protocol, func(t *testing.T) {
			env := newInspectEnv(t, policy, protocol)
			if status, body := env.do(http.MethodGet, "/any/path", nil, nil); status != http.StatusOK || body != inspectLarge {
				t.Fatalf("default GET = %d, %d bytes", status, len(body))
			}
			if status, _ := env.do(http.MethodHead, "/any/path", nil, nil); status != http.StatusOK {
				t.Fatalf("default HEAD = %d", status)
			}
			before := env.hits.Load()
			for name, test := range map[string]struct {
				method string
				body   io.Reader
				header http.Header
				want   int
			}{
				"post":                     {http.MethodPost, strings.NewReader("data"), nil, http.StatusForbidden},
				"put":                      {http.MethodPut, strings.NewReader("data"), nil, http.StatusForbidden},
				"delete":                   {http.MethodDelete, nil, nil, http.StatusForbidden},
				"get with body":            {http.MethodGet, strings.NewReader("data"), nil, http.StatusRequestEntityTooLarge},
				"get with chunked body":    {http.MethodGet, io.NopCloser(strings.NewReader("data")), nil, http.StatusRequestEntityTooLarge},
				"get with method override": {http.MethodGet, nil, http.Header{"X-Method-Override": {"PUT"}}, http.StatusForbidden},
			} {
				if status, text := env.do(test.method, "/x", test.body, test.header); status != test.want {
					t.Errorf("%s: status = %d (%s), want %d", name, status, text, test.want)
				}
			}
			if env.hits.Load() != before {
				t.Errorf("denied requests reached upstream (%d hits)", env.hits.Load()-before)
			}
			env.closeIdle()
		})
	}
}

func TestConnectRequiresInterceptionForInspectHosts(t *testing.T) {
	policy := inspectPolicy(t, config.Client{InterceptMode: config.ModeOpaque, InspectHosts: []string{"allowed.example"}})
	h := &Handler{Policy: policy, Resolver: fixedResolver{netip.MustParseAddr("93.184.216.34")}}
	defer h.Close()
	request := httptest.NewRequest(http.MethodConnect, "allowed.example:443", nil)
	request.Header.Set("Proxy-Authorization", "Bearer 012345678901234567890123")
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "inspect_hosts") {
		t.Fatalf("response = %d %q, want 503 requiring interception", recorder.Code, recorder.Body.String())
	}
}

func TestEncodedPathsOnlyMatterToPathPrefixRules(t *testing.T) {
	const scoped = "/@scope%2fpkg"
	for _, test := range []struct {
		name string
		rule config.Rule
		want int
	}{
		{"method-only rule", config.Rule{Host: "allowed.example", Methods: []string{"GET"}}, http.StatusOK},
		{"path prefix rule", config.Rule{Host: "allowed.example", Methods: []string{"GET"}, PathPrefixes: []string{"/"}}, http.StatusForbidden},
		{"default read-only policy", config.Rule{}, http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := config.Client{InterceptMode: config.ModeInspect}
			if test.rule.Host != "" {
				client.AllowedRules = []config.Rule{test.rule}
			}
			env := newInspectEnv(t, inspectPolicy(t, client), "h2")
			if status, text := env.do(http.MethodGet, scoped, nil, nil); status != test.want {
				t.Fatalf("GET %s = %d (%s), want %d", scoped, status, text, test.want)
			}
			env.closeIdle()
		})
	}
}

// An HTTP/2 upstream often omits Content-Length. The HTTP/1.1 downstream must
// still be able to tell where the body ends without waiting for a close.
func TestInspectFramesUnknownLengthUpstreamBodyForHTTP1(t *testing.T) {
	policy := inspectPolicy(t, config.Client{InterceptMode: config.ModeInspect})
	for _, protocol := range []string{"http/1.1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			env := newInspectEnv(t, policy, protocol)
			// With keep-alive the proxy cannot end the body by closing the connection.
			env.transport.DisableKeepAlives = false
			started := time.Now()
			if status, body := env.do(http.MethodGet, "/unknown-length", nil, nil); status != http.StatusOK || body != inspectLarge {
				t.Fatalf("GET = %d, %d bytes: %.80s", status, len(body), body)
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("response took %v; the body end was not signalled", elapsed)
			}
		})
	}
}

// A client that is still uploading when the proxy denies the request must see
// the denial, not a connection reset.
func TestDeniedRequestDrainsLargeBodyBeforeClosing(t *testing.T) {
	policy := inspectPolicy(t, config.Client{
		InterceptMode: config.ModeInspect,
		AllowedRules:  []config.Rule{{Host: "allowed.example", Methods: []string{"PUT"}, PathPrefixes: []string{"/up/"}, MaxRequestBytes: 10}},
	})
	env := newInspectEnv(t, policy, "http/1.1")
	for _, size := range []int{64 << 10, 1 << 20, 8 << 20} {
		// Method not permitted (default for the path), declared length.
		if status, text := env.do(http.MethodPost, "/x", strings.NewReader(strings.Repeat("a", size)), nil); status != http.StatusForbidden {
			t.Errorf("POST %d bytes = %d (%.80s), want 403", size, status, text)
		}
	}
	// Cut off at max_request_bytes while the client keeps streaming chunked data.
	body := io.NopCloser(strings.NewReader(strings.Repeat("a", 4<<20)))
	if status, text := env.do(http.MethodPut, "/up/x", body, nil); status == http.StatusOK {
		t.Errorf("chunked PUT over the cap = %d (%.80s), want a failure", status, text)
	}
}
