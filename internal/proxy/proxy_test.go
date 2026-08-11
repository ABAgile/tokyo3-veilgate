package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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
	"github.com/abagile/veilgate/internal/secret"
)

const testPlaceholder = "VEILGATED_SECRET_0123456789abcdef"

type fixedResolver struct{ address netip.Addr }

func (r fixedResolver) Resolve(context.Context, string) (netip.Addr, error) { return r.address, nil }

func testPolicy(t *testing.T) *config.File {
	t.Helper()
	f := &config.File{Clients: []config.Client{{
		Name: "agent", Token: "012345678901234567890123",
		AllowedHosts: []string{"allowed.example"}, AllowedPorts: []int{80},
	}}}
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	return f
}

func storedFlows(t *testing.T, store *flow.Store, expected int) []flow.Flow {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		items, err := store.List(context.Background(), flow.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if len(items) >= expected {
			return items
		}
		time.Sleep(10 * time.Millisecond)
	}
	items, _ := store.List(context.Background(), flow.Filter{})
	return items
}

func TestCloseWaitsForFlowRecording(t *testing.T) {
	store := flow.NewStore(10)
	h := &Handler{Store: store}
	h.recordFlow(flow.Flow{Host: "example.com"})
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	items, err := store.List(context.Background(), flow.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Host != "example.com" {
		t.Fatalf("recorded flows = %#v", items)
	}
}

func TestRecordQueueDropsInsteadOfBlocking(t *testing.T) {
	entered := make(chan struct{}, recordWorkerCount)
	release := make(chan struct{})
	var callbacks atomic.Int32
	var logs bytes.Buffer
	h := &Handler{
		Log: slog.New(slog.NewTextHandler(&logs, nil)),
		Record: func(context.Context, flow.Flow) {
			if callbacks.Add(1) <= recordWorkerCount {
				entered <- struct{}{}
				<-release
			}
		},
	}
	for range recordQueueCapacity + recordWorkerCount {
		h.recordFlow(flow.Flow{Host: "example.com"})
	}
	for range recordWorkerCount {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("record workers did not start")
		}
	}
	start := time.Now()
	h.recordFlow(flow.Flow{Host: "example.com"})
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("record enqueue blocked for %s", elapsed)
	}
	if got := h.recordDropped.Load(); got == 0 {
		t.Fatal("record queue did not report a dropped job")
	}
	if !strings.Contains(logs.String(), "flow records dropped under backpressure") {
		t.Fatalf("drop warning = %q", logs.String())
	}
	close(release)
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDeniedRecordWaitsForQueueCapacity(t *testing.T) {
	entered := make(chan struct{}, recordWorkerCount)
	release := make(chan struct{})
	var callbacks atomic.Int32
	h := &Handler{Record: func(context.Context, flow.Flow) {
		if callbacks.Add(1) <= recordWorkerCount {
			entered <- struct{}{}
			<-release
		}
	}}
	for range recordWorkerCount {
		h.recordFlow(flow.Flow{Decision: "allowed"})
	}
	for range recordWorkerCount {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("record workers did not start")
		}
	}
	for range recordQueueCapacity {
		h.recordFlow(flow.Flow{Decision: "allowed"})
	}

	go func() {
		time.Sleep(recordDeniedEnqueueTimeout / 4)
		close(release)
	}()
	h.recordFlow(flow.Flow{Decision: "denied"})
	if got := h.recordDropped.Load(); got != 0 {
		t.Fatalf("denied record was dropped: %d", got)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProxyForwardsAuthorizedHTTPAndSanitizesCredentials(t *testing.T) {
	var gotProxyAuthorization string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProxyAuthorization = r.Header.Get("Proxy-Authorization")
		_, _ = io.WriteString(w, "hello")
	}))
	defer upstream.Close()
	upstreamAddress := upstream.Listener.Addr().String()

	store := flow.NewStore(10)
	h := &Handler{
		Policy: testPolicy(t), Resolver: fixedResolver{netip.MustParseAddr("93.184.216.34")}, Store: store,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstreamAddress)
		},
	}
	req := httptest.NewRequest(http.MethodGet, "http://allowed.example/resource", nil)
	req.Header.Set("Proxy-Authorization", "Bearer 012345678901234567890123")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "hello" {
		t.Fatalf("response = %d %q", rec.Code, rec.Body.String())
	}
	if gotProxyAuthorization != "" {
		t.Fatalf("upstream received Proxy-Authorization %q", gotProxyAuthorization)
	}
	items := storedFlows(t, store, 1)
	if len(items) != 1 || items[0].Decision != "allowed" || items[0].Client != "agent" {
		t.Fatalf("flows = %#v", items)
	}
}

func TestProxyMediatesPlainHTTPResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Reflected-Secret", "real-api-key")
		_, _ = io.WriteString(w, "plain response real-api-key")
	}))
	defer upstream.Close()

	store := flow.NewStore(10)
	h := &Handler{
		Policy: testPolicy(t), Resolver: fixedResolver{netip.MustParseAddr("93.184.216.34")},
		Store: store, Secrets: proxyTestBroker(t),
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
		},
	}
	defer h.Close()
	request := httptest.NewRequest(http.MethodGet, "http://allowed.example/resource", nil)
	request.Header.Set("Proxy-Authorization", "Bearer 012345678901234567890123")
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "plain response "+testPlaceholder {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("X-Reflected-Secret"); got != testPlaceholder {
		t.Fatalf("response secret header = %q", got)
	}
	items := storedFlows(t, store, 1)
	if len(items) != 1 || len(items[0].ResponseSecretNames) != 1 || items[0].ResponseSecretNames[0] != "api_key" || items[0].Capture.ResponseBody == nil || items[0].Capture.ResponseBody.Text != "plain response [secret:api_key]" {
		t.Fatalf("flow = %#v", items)
	}
}

func TestProxyStreamsPlainHTTPEventsBeforeUpstreamCompletion(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("upstream writer does not support flushing")
			return
		}
		_, _ = io.WriteString(w, "data: real-api-key\n\n")
		flusher.Flush()
		<-release
	}))
	defer upstream.Close()
	defer close(release)

	h := &Handler{
		Policy: testPolicy(t), Resolver: fixedResolver{netip.MustParseAddr("93.184.216.34")}, Secrets: proxyTestBroker(t),
		CaptureLimit: 4096, MediationLimit: 4096,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
		},
	}
	defer h.Close()
	proxyServer := httptest.NewServer(h)
	defer proxyServer.Close()
	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	responseCh := make(chan struct {
		response *http.Response
		err      error
	}, 1)
	go func() {
		request, err := http.NewRequest(http.MethodGet, "http://allowed.example/stream", nil)
		if err == nil {
			request.Header.Set("Proxy-Authorization", "Bearer 012345678901234567890123")
		}
		response, err := client.Do(request)
		responseCh <- struct {
			response *http.Response
			err      error
		}{response: response, err: err}
	}()

	var result struct {
		response *http.Response
		err      error
	}
	select {
	case result = <-responseCh:
	case <-time.After(time.Second):
		t.Fatal("plain HTTP streaming response did not return headers before upstream completion")
	}
	if result.err != nil {
		t.Fatal(result.err)
	}
	defer result.response.Body.Close()
	firstEvent := make([]byte, len("data: "+testPlaceholder+"\n\n"))
	if _, err := io.ReadFull(result.response.Body, firstEvent); err != nil {
		t.Fatal(err)
	}
	if string(firstEvent) != "data: "+testPlaceholder+"\n\n" {
		t.Fatalf("first event = %q", firstEvent)
	}
}

func TestProxyBlocksSecretPlaceholderOverPlainHTTP(t *testing.T) {
	broker, err := secret.New(secret.File{Secrets: []secret.Definition{{
		Name: "api_key", ValueEnv: "TEST_API_KEY",
		Placeholder: "VEILGATED_SECRET_0123456789abcdef",
		Clients:     []string{"agent"}, AllowedHosts: []string{"allowed.example"},
	}}}, func(string) (string, bool) { return "real-api-key", true })
	if err != nil {
		t.Fatal(err)
	}
	store := flow.NewStore(10)
	h := &Handler{
		Policy: testPolicy(t), Resolver: fixedResolver{netip.MustParseAddr("93.184.216.34")},
		Store: store, Secrets: broker,
	}
	req := httptest.NewRequest(http.MethodGet, "http://allowed.example/resource", nil)
	req.Header.Set("Proxy-Authorization", "Bearer 012345678901234567890123")
	req.Header.Set("Authorization", "Bearer VEILGATED_SECRET_0123456789abcdef")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	items := storedFlows(t, store, 1)
	if len(items) != 1 || items[0].Decision != "denied" || !strings.Contains(items[0].Reason, "plaintext") {
		t.Fatalf("flows = %#v", items)
	}
}

func TestProxyRequiresAuthenticationBeforePolicy(t *testing.T) {
	h := &Handler{Policy: testPolicy(t), Store: flow.NewStore(10)}
	req := httptest.NewRequest(http.MethodGet, "http://denied.example/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Proxy-Authenticate"); !strings.Contains(got, "Bearer") {
		t.Fatalf("Proxy-Authenticate = %q", got)
	}
}

func TestProxyAcceptsMatchingBasicIdentity(t *testing.T) {
	h := &Handler{Policy: testPolicy(t), Store: flow.NewStore(10)}
	req := httptest.NewRequest(http.MethodGet, "http://denied.example/", nil)
	credential := base64.StdEncoding.EncodeToString([]byte("agent:012345678901234567890123"))
	req.Header.Set("Proxy-Authorization", "Basic "+credential)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want policy denial after successful auth", rec.Code)
	}
}

func TestConnectTunnelCompletesWhenClientCloses(t *testing.T) {
	store := flow.NewStore(10)
	h := &Handler{
		Policy: testPolicy(t), Resolver: fixedResolver{netip.MustParseAddr("93.184.216.34")}, Store: store,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			proxySide, upstreamSide := net.Pipe()
			go func() {
				defer upstreamSide.Close()
				_, _ = io.Copy(io.Discard, upstreamSide)
			}()
			return proxySide, nil
		},
	}
	server := httptest.NewServer(h)
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "http://")
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT allowed.example:80 HTTP/1.1\r\nHost: allowed.example:80\r\nProxy-Authorization: Bearer 012345678901234567890123\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("CONNECT response = %q, %v", status, err)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	if _, err := io.WriteString(conn, "hello"); err != nil {
		t.Fatal(err)
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = io.Copy(io.Discard, reader)
	_ = conn.Close()

	deadline := time.Now().Add(time.Second)
	for len(storedFlows(t, store, 1)) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	items := storedFlows(t, store, 1)
	if len(items) != 1 || items[0].BytesSent != 5 {
		t.Fatalf("flows = %#v", items)
	}
}

func TestProxyInterceptsHTTPSAndRecordsSanitizedRequest(t *testing.T) {
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
	rootPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("append interception root")
	}
	upstreamTLS, err := authority.TLSConfig("allowed.example")
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: real-api-key\n\n")
			return
		}
		if r.URL.Path != "/v1/responses" || r.URL.Query().Get("token") != "real-api-key" || r.URL.Query().Get("model") != "test" {
			t.Errorf("upstream URL = %q", r.URL.String())
		}
		if got := r.Header.Get("Authorization"); got != "Bearer real-api-key" {
			t.Errorf("upstream Authorization = %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != `{"prompt":"hello","token":"real-api-key"}` {
			t.Errorf("upstream body = %q err = %v", body, err)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Reflected-Token", "real-api-key")
		_, _ = io.WriteString(w, "intercepted real-api-key")
	}))
	upstream.TLS = upstreamTLS
	upstream.StartTLS()
	defer upstream.Close()
	upstreamRoots := x509.NewCertPool()
	if !upstreamRoots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("append upstream root")
	}

	policy := &config.File{Clients: []config.Client{{
		Name: "agent", Token: "012345678901234567890123",
		AllowedHosts: []string{"allowed.example"}, AllowedPorts: []int{443},
	}}}
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	secretBroker, err := secret.New(secret.File{Secrets: []secret.Definition{{
		Name: "api_key", ValueEnv: "TEST_API_KEY",
		Placeholder: "VEILGATED_SECRET_0123456789abcdef",
		Clients:     []string{"agent"}, AllowedHosts: []string{"allowed.example"},
	}}}, func(string) (string, bool) { return "real-api-key", true })
	if err != nil {
		t.Fatal(err)
	}
	store := flow.NewStore(10)
	h := &Handler{
		Policy: policy, Resolver: fixedResolver{netip.MustParseAddr("93.184.216.34")},
		Store: store, Interceptor: authority, Secrets: secretBroker,
		UpstreamTLSConfig: &tls.Config{RootCAs: upstreamRoots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
		},
	}
	proxyServer := httptest.NewServer(h)
	defer proxyServer.Close()
	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true, ForceAttemptHTTP2: true,
		ProxyConnectHeader: http.Header{"Proxy-Authorization": {"Bearer 012345678901234567890123"}},
		TLSClientConfig:    &tls.Config{RootCAs: clientRoots, MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	request, err := http.NewRequest(http.MethodPost, "https://allowed.example/v1/responses?token=VEILGATED_SECRET_0123456789abcdef&model=test", strings.NewReader(`{"token":"VEILGATED_SECRET_0123456789abcdef","prompt":"hello"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer VEILGATED_SECRET_0123456789abcdef")
	request.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	transport.CloseIdleConnections()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "intercepted VEILGATED_SECRET_0123456789abcdef" || resp.Header.Get("X-Reflected-Token") != "VEILGATED_SECRET_0123456789abcdef" {
		t.Fatalf("body = %q reflected header = %q", body, resp.Header.Get("X-Reflected-Token"))
	}
	streamResponse, err := client.Get("https://allowed.example/stream")
	if err != nil {
		t.Fatal(err)
	}
	streamBody, err := io.ReadAll(streamResponse.Body)
	_ = streamResponse.Body.Close()
	if err != nil || string(streamBody) != "data: VEILGATED_SECRET_0123456789abcdef\n\n" {
		t.Fatalf("stream body = %q err = %v", streamBody, err)
	}

	deadline := time.Now().Add(time.Second)
	for len(storedFlows(t, store, 1)) < 4 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	var requestFlow, streamFlow, sessionFlow *flow.Flow
	for _, item := range storedFlows(t, store, 1) {
		copy := item
		if item.Method == http.MethodPost {
			requestFlow = &copy
		}
		if item.Method == http.MethodGet && item.Path == "/stream" {
			streamFlow = &copy
		}
		if item.Method == http.MethodConnect {
			sessionFlow = &copy
		}
	}
	if requestFlow == nil || streamFlow == nil || sessionFlow == nil || requestFlow.SessionID == "" || requestFlow.SessionID != sessionFlow.SessionID {
		t.Fatalf("grouped intercepted flows missing: %#v", storedFlows(t, store, 1))
	}
	if requestFlow.Mode != "intercepted-h2" || requestFlow.DownstreamProtocol != "h2" || requestFlow.UpstreamProtocol == "" || requestFlow.Path != "/v1/responses" || strings.Contains(requestFlow.Path, "token") || len(requestFlow.SecretNames) != 1 || requestFlow.SecretNames[0] != "api_key" || len(requestFlow.ResponseSecretNames) != 1 || requestFlow.Capture.Query != "model=test&token=[secret:api_key]" || requestFlow.Capture.RequestBody == nil || requestFlow.Capture.RequestBody.Text != `{"prompt":"hello","token":"[secret:api_key]"}` || requestFlow.Capture.ResponseBody == nil || requestFlow.Capture.ResponseBody.Text != "intercepted [secret:api_key]" {
		t.Fatalf("intercepted flow = %#v", requestFlow)
	}
	if streamFlow.DownstreamProtocol != "h2" || streamFlow.UpstreamProtocol == "" || streamFlow.Capture.ResponseBody == nil || streamFlow.Capture.ResponseBody.Text != "data: [secret:api_key]\n\n" {
		t.Fatalf("streaming flow = %#v", streamFlow)
	}
	encoded, err := json.Marshal(storedFlows(t, store, 1))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "real-api-key") || strings.Contains(string(encoded), "VEILGATED_SECRET_") {
		t.Fatalf("flow capture leaked secret material: %s", encoded)
	}
}

func TestProxyMediatesWebSocketTextFrames(t *testing.T) {
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
	rootPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("append interception root")
	}
	upstreamTLS, err := authority.TLSConfig("allowed.example")
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validNoContextDeflate(r.Header.Get("Sec-WebSocket-Extensions")) {
			t.Errorf("upstream extensions = %q", r.Header.Get("Sec-WebSocket-Extensions"))
		}
		if r.URL.Query().Get("token") != "real-api-key" {
			t.Errorf("upstream query = %q", r.URL.RawQuery)
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover\r\n\r\n", webSocketAccept(r.Header.Get("Sec-WebSocket-Key")))
		_ = rw.Flush()
		frame, err := readWebSocketFrame(rw.Reader, true, 1<<20)
		if err != nil {
			t.Errorf("read client frame: %v", err)
			return
		}
		payload := frame.payload
		if frame.compressed {
			payload, err = decompressWebSocketMessage(payload, 1<<20)
		}
		if err != nil || string(payload) != `{"token":"real-api-key"}` {
			t.Errorf("upstream frame = %q err = %v", payload, err)
		}
		endpoint := &wsEndpoint{writer: rw, writeMask: false, compression: true}
		if err := endpoint.write(wsFrame{fin: true, compressed: true, opcode: wsText, payload: []byte(`{"echo":"real-api-key"}`)}); err != nil {
			t.Errorf("write server frame: %v", err)
		}
		_ = endpoint.write(wsFrame{fin: true, opcode: wsClose, payload: wsClosePayload(1000, "done")})
		_ = rw.Flush()
	}))
	upstream.TLS = upstreamTLS
	upstream.StartTLS()
	defer upstream.Close()

	policy := &config.File{Clients: []config.Client{{
		Name: "agent", Token: "012345678901234567890123",
		AllowedHosts: []string{"allowed.example"}, AllowedPorts: []int{443},
	}}}
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	broker, err := secret.New(secret.File{Secrets: []secret.Definition{{
		Name: "api_key", ValueEnv: "TEST_API_KEY", Placeholder: testPlaceholder,
		Clients: []string{"agent"}, AllowedHosts: []string{"allowed.example"},
	}}}, func(string) (string, bool) { return "real-api-key", true })
	if err != nil {
		t.Fatal(err)
	}
	store := flow.NewStore(10)
	h := &Handler{
		Policy: policy, Resolver: fixedResolver{netip.MustParseAddr("93.184.216.34")},
		Store: store, Interceptor: authority, Secrets: broker,
		UpstreamTLSConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
		},
	}
	proxyServer := httptest.NewServer(h)
	defer proxyServer.Close()
	proxyURL, _ := url.Parse(proxyServer.URL)
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(conn, "CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\nProxy-Authorization: Bearer 012345678901234567890123\r\n\r\n")
	reader := bufio.NewReader(conn)
	connectResponse, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || connectResponse.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT response = %#v err = %v", connectResponse, err)
	}
	tlsClient := tls.Client(&bufferedConn{Conn: conn, reader: reader}, &tls.Config{RootCAs: roots, ServerName: "allowed.example", MinVersion: tls.VersionTLS12})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	_, _ = fmt.Fprintf(tlsClient, "GET /socket?token=%s HTTP/1.1\r\nHost: allowed.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n", testPlaceholder, key)
	websocketReader := bufio.NewReader(tlsClient)
	upgradeResponse, err := http.ReadResponse(websocketReader, &http.Request{Method: http.MethodGet})
	if err != nil || upgradeResponse.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade response = %#v err = %v", upgradeResponse, err)
	}
	clientEndpoint := &wsEndpoint{writer: tlsClient, writeMask: true, compression: true}
	if err := clientEndpoint.write(wsFrame{fin: true, compressed: true, opcode: wsText, payload: []byte(`{"token":"` + testPlaceholder + `"}`)}); err != nil {
		t.Fatal(err)
	}
	serverFrame, err := readWebSocketFrame(websocketReader, false, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	serverPayload := serverFrame.payload
	if serverFrame.compressed {
		serverPayload, err = decompressWebSocketMessage(serverPayload, 1<<20)
	}
	if err != nil || string(serverPayload) != `{"echo":"`+testPlaceholder+`"}` {
		t.Fatalf("server frame = %q err = %v", serverPayload, err)
	}
	_, _ = readWebSocketFrame(websocketReader, false, 1<<20)
	_ = tlsClient.Close()

	deadline := time.Now().Add(time.Second)
	var websocketFlow *flow.Flow
	for time.Now().Before(deadline) {
		for _, item := range storedFlows(t, store, 1) {
			if item.Mode == "websocket" {
				copy := item
				websocketFlow = &copy
			}
		}
		if websocketFlow != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if websocketFlow == nil || len(websocketFlow.Capture.WebSocketMessages) != 2 || websocketFlow.Capture.WebSocketMessages[0].Text != `{"token":"[secret:api_key]"}` || websocketFlow.Capture.WebSocketMessages[1].Text != `{"echo":"[secret:api_key]"}` {
		t.Fatalf("WebSocket flow = %#v", websocketFlow)
	}
	encoded, err := json.Marshal(websocketFlow)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "real-api-key") || strings.Contains(string(encoded), testPlaceholder) {
		t.Fatalf("WebSocket capture leaked secret material: %s", encoded)
	}
}

func TestValidateInterceptedRequest(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		host   string
		url    string
		modify func(*http.Request)
		ok     bool
	}{
		{name: "origin form", method: http.MethodGet, host: "allowed.example", url: "/v1/responses", ok: true},
		{name: "absolute matching", method: http.MethodPost, host: "allowed.example", url: "https://allowed.example/v1/responses", ok: true},
		{name: "host mismatch", method: http.MethodGet, host: "other.example", url: "/", ok: false},
		{name: "absolute mismatch", method: http.MethodGet, host: "allowed.example", url: "https://other.example/", ok: false},
		{name: "nested connect", method: http.MethodConnect, host: "allowed.example", url: "/", ok: false},
		{name: "websocket", method: http.MethodGet, host: "allowed.example", url: "/", modify: func(r *http.Request) { r.Header.Set("Upgrade", "websocket") }, ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.url, nil)
			req.Host = tc.host
			if tc.modify != nil {
				tc.modify(req)
			}
			err := validateInterceptedRequest(req, "allowed.example", 443)
			if (err == nil) != tc.ok {
				t.Fatalf("validateInterceptedRequest() error = %v, want success %v", err, tc.ok)
			}
		})
	}
}

func TestProxyRejectsHostMismatch(t *testing.T) {
	h := &Handler{Policy: testPolicy(t), Store: flow.NewStore(10)}
	req := httptest.NewRequest(http.MethodGet, "http://allowed.example/", nil)
	req.Host = "other.example"
	req.Header.Set("Proxy-Authorization", "Bearer 012345678901234567890123")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}
