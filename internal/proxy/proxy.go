// Package proxy implements veilgated's authenticated, deny-by-default forward proxy.
package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/abagile/tokyo3-base/guard"

	"github.com/abagile/veilgate/internal/config"
	"github.com/abagile/veilgate/internal/flow"
)

const maxErrorReason = 160

// Recorder receives completed, sanitized flows.
type Recorder func(context.Context, flow.Flow)

type flowRecordJob struct {
	ctx  context.Context
	item flow.Flow
}

const (
	defaultRecordQueueCapacity   = 256
	defaultRecordWorkerCount     = 4
	recordDeniedEnqueueTimeout   = 100 * time.Millisecond
	recordDropNoticeInterval     = 10 * time.Second
	recordShutdownTimeout        = 5 * time.Second
	defaultSessionIdleTimeout    = 10 * time.Minute
	defaultSessionMaxDuration    = 2 * time.Hour
	defaultResponseHeaderTimeout = 60 * time.Second
)

// Interceptor supplies destination-bound TLS server configurations.
type Interceptor interface {
	TLSConfig(host string) (*tls.Config, error)
}

// SecretBroker substitutes scoped placeholders, scrubs response values, and
// sanitizes retained captures without exposing host values.
type SecretBroker interface {
	Apply(req *http.Request, client, host string, secure bool) ([]string, error)
	SubstituteQuery(*url.URL, string, string, bool) ([]string, error)
	SubstituteBody(string, []byte, string, string, bool) ([]byte, []string, bool, error)
	SubstituteJSONMessage([]byte, string, string) ([]byte, []string, error)
	Scrub([]byte, string, string) ([]byte, []string)
	Sanitize([]byte) []byte
	ContainsPlaceholder([]byte) bool
	PlaceholderNames([]byte) []string
}

// OAuthBroker virtualizes configured OAuth token responses and implements the
// SecretBroker contract for subsequent virtual-token requests.
type OAuthBroker interface {
	SecretBroker
	ObserveTokenResponse(*http.Request, *http.Response, []byte, string, string) ([]byte, []string, error)
}

// CombineBrokers returns a single broker that applies each non-nil broker in
// order. It keeps static secrets and dynamic OAuth tokens independently scoped.
// Typed-nil pointer implementations are ignored as well; optional concrete
// brokers are commonly converted to this interface before being combined.
func CombineBrokers(brokers ...SecretBroker) SecretBroker {
	active := make([]SecretBroker, 0, len(brokers))
	for _, broker := range brokers {
		if broker == nil {
			continue
		}
		value := reflect.ValueOf(broker)
		switch value.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			if value.IsNil() {
				continue
			}
		}
		active = append(active, broker)
	}
	if len(active) == 0 {
		return nil
	}
	if len(active) == 1 {
		return active[0]
	}
	return brokerChain{brokers: active}
}

type brokerChain struct{ brokers []SecretBroker }

func (c brokerChain) Apply(req *http.Request, client, host string, secure bool) ([]string, error) {
	var names []string
	for _, broker := range c.brokers {
		current, err := broker.Apply(req, client, host, secure)
		if err != nil {
			return nil, err
		}
		names = mergeNames(names, current)
	}
	return names, nil
}
func (c brokerChain) SubstituteQuery(target *url.URL, client, host string, secure bool) ([]string, error) {
	var names []string
	for _, broker := range c.brokers {
		current, err := broker.SubstituteQuery(target, client, host, secure)
		if err != nil {
			return nil, err
		}
		names = mergeNames(names, current)
	}
	return names, nil
}
func (c brokerChain) SubstituteBody(contentType string, body []byte, client, host string, secure bool) ([]byte, []string, bool, error) {
	var names []string
	supported := false
	for _, broker := range c.brokers {
		transformed, current, brokerSupported, err := broker.SubstituteBody(contentType, body, client, host, secure)
		if err != nil {
			return nil, nil, brokerSupported, err
		}
		body, supported = transformed, supported || brokerSupported
		names = mergeNames(names, current)
	}
	return body, names, supported, nil
}
func (c brokerChain) SubstituteJSONMessage(body []byte, client, host string) ([]byte, []string, error) {
	var names []string
	for _, broker := range c.brokers {
		transformed, current, err := broker.SubstituteJSONMessage(body, client, host)
		if err != nil {
			return nil, nil, err
		}
		body = transformed
		names = mergeNames(names, current)
	}
	return body, names, nil
}
func (c brokerChain) Scrub(data []byte, client, host string) ([]byte, []string) {
	var names []string
	for _, broker := range c.brokers {
		var current []string
		data, current = broker.Scrub(data, client, host)
		names = mergeNames(names, current)
	}
	return data, names
}
func (c brokerChain) Sanitize(data []byte) []byte {
	for _, broker := range c.brokers {
		data = broker.Sanitize(data)
	}
	return data
}
func (c brokerChain) ContainsPlaceholder(data []byte) bool {
	for _, broker := range c.brokers {
		if broker.ContainsPlaceholder(data) {
			return true
		}
	}
	return false
}
func (c brokerChain) PlaceholderNames(data []byte) []string {
	var names []string
	for _, broker := range c.brokers {
		names = mergeNames(names, broker.PlaceholderNames(data))
	}
	return names
}

// Handler is an authenticated HTTP forward proxy. When Interceptor is set,
// HTTPS CONNECT sessions are terminated and their HTTP/1.1 or HTTP/2 requests
// mediated unless the authenticated client marks the destination as opaque;
// otherwise CONNECT remains an explicitly identified opaque tunnel.
type Handler struct {
	Policy                        *config.File
	Resolver                      Resolver
	Store                         *flow.Store
	Record                        Recorder
	Log                           *slog.Logger
	Interceptor                   Interceptor
	Secrets                       SecretBroker
	OAuth                         OAuthBroker
	UpstreamTLSConfig             *tls.Config
	DialTimeout                   time.Duration
	SessionIdleTimeout            time.Duration
	SessionMaxDuration            time.Duration
	UpstreamResponseHeaderTimeout time.Duration
	CaptureLimit                  int64
	MediationLimit                int64
	RecordQueueCapacity           int
	RecordWorkers                 int
	DialContext                   func(context.Context, string, string) (net.Conn, error)

	transportMu        sync.Mutex
	transports         map[upstreamTransportKey]*cachedUpstreamTransport
	drainingTransports []*cachedUpstreamTransport
	transportClosed    bool

	recordMu           sync.Mutex
	recordClosed       bool
	recordQueue        chan flowRecordJob
	recordContext      context.Context
	recordCancel       context.CancelFunc
	recordWG           sync.WaitGroup
	recordSubmitWG     sync.WaitGroup
	recordDropped      atomic.Uint64
	recordDropNoticeAt atomic.Int64
}

func (h *Handler) recordQueueCapacity() int {
	if h.RecordQueueCapacity > 0 {
		return h.RecordQueueCapacity
	}
	return defaultRecordQueueCapacity
}

func (h *Handler) recordWorkerCount() int {
	if h.RecordWorkers > 0 {
		return h.RecordWorkers
	}
	return defaultRecordWorkerCount
}

func (h *Handler) sessionIdleTimeout() time.Duration {
	if h.SessionIdleTimeout > 0 {
		return h.SessionIdleTimeout
	}
	return defaultSessionIdleTimeout
}

func (h *Handler) sessionMaxDuration() time.Duration {
	if h.SessionMaxDuration > 0 {
		return h.SessionMaxDuration
	}
	return defaultSessionMaxDuration
}

func (h *Handler) upstreamResponseHeaderTimeout() time.Duration {
	if h.UpstreamResponseHeaderTimeout > 0 {
		return h.UpstreamResponseHeaderTimeout
	}
	return defaultResponseHeaderTimeout
}

func (h *Handler) dialTimeout() time.Duration {
	if h.DialTimeout > 0 {
		return h.DialTimeout
	}
	return 10 * time.Second
}

// ServeHTTP authenticates and routes one proxy request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	sessionContext, cancel := context.WithTimeout(r.Context(), h.sessionMaxDuration())
	defer cancel()
	r = r.WithContext(sessionContext)
	f := flow.Flow{StartedAt: started, Method: r.Method, Decision: "denied", Mode: "direct", DownstreamProtocol: protocolLabel(r.ProtoMajor, r.ProtoMinor)}
	defer func() {
		f.Duration = time.Since(started)
		h.recordFlow(f)
	}()

	client, ok := h.authenticate(r)
	if !ok {
		f.Trace("proxy-authentication", "fail", "credential rejected")
		f.Reason = "proxy authentication required"
		w.Header().Set("Proxy-Authenticate", `Bearer realm="veilgate"`)
		http.Error(w, f.Reason, http.StatusProxyAuthRequired)
		return
	}
	f.Client = client.Name
	f.Trace("proxy-authentication", "pass", "client "+client.Name)

	host, port, scheme, err := requestTarget(r)
	if err != nil {
		f.Trace("request-target", "fail", safeReason(err))
		f.Reason = safeReason(err)
		http.Error(w, f.Reason, http.StatusBadRequest)
		return
	}
	f.Host, f.Port, f.Scheme = host, port, scheme
	f.Trace("request-target", "pass", net.JoinHostPort(host, strconv.Itoa(port)))
	if r.Method == http.MethodConnect {
		f.SessionID, err = newSessionID()
		if err != nil {
			f.Reason = "generate CONNECT session identifier"
			http.Error(w, f.Reason, http.StatusInternalServerError)
			return
		}
	}
	if r.Method != http.MethodConnect && r.URL != nil {
		f.Path = sanitizeText(h.Secrets, sanitizedPath(r.URL))
	}
	if !client.Allows(host, port) {
		f.Trace("destination-acl", "fail", "client policy denied destination")
		f.Reason = "destination is not allowed by client policy"
		http.Error(w, f.Reason, http.StatusForbidden)
		return
	}
	f.Trace("destination-acl", "pass", destinationPolicyDetail(client))

	ip, err := h.resolver().Resolve(r.Context(), host)
	if err != nil {
		f.Trace("destination-ip", "fail", safeReason(err))
		f.Reason = safeReason(err)
		http.Error(w, f.Reason, http.StatusForbidden)
		return
	}
	f.DestinationIP = ip.String()
	f.Trace("destination-ip", "pass", ip.String())
	f.Decision = "allowed"

	if r.Method == http.MethodConnect {
		opaque := client.UsesOpaqueTunnel(host)
		if h.Interceptor != nil && !opaque {
			f.Mode = "intercepted-session"
			f.Trace("tls-mediation", "pass", "HTTP/2 or HTTP/1.1 interception selected")
			f.Status, f.BytesSent, f.BytesReceived, f.Reason = h.intercept(w, r, client, host, port, f.SessionID)
			return
		}
		if h.Secrets != nil && !opaque {
			f.Decision = "denied"
			f.Status = http.StatusServiceUnavailable
			f.Reason = "secret broker requires TLS interception"
			f.Trace("tls-mediation", "fail", f.Reason)
			http.Error(w, f.Reason, http.StatusServiceUnavailable)
			return
		}
		f.Mode = "opaque-tunnel"
		if opaque {
			f.Trace("tls-mediation", "pass", "opaque tunnel selected by client policy")
		} else {
			f.Trace("tls-mediation", "pass", "opaque tunnel selected")
		}
		f.Status, f.BytesSent, f.BytesReceived, f.Reason = h.tunnel(w, r, ip, port)
		return
	}
	if h.Secrets != nil {
		var discarded flow.Flow
		if err := h.mediateRequest(r, client.Name, host, false, &discarded); err != nil {
			f.Decision = "denied"
			f.Status = http.StatusForbidden
			f.Reason = safeReason(err)
			f.Trace("secret-policy", "fail", f.Reason)
			http.Error(w, f.Reason, http.StatusForbidden)
			return
		}
		f.SecretNames = discarded.SecretNames
		f.Trace("secret-policy", "pass", secretTraceDetail(f.SecretNames))
	}
	f.Status, f.BytesSent, f.BytesReceived, f.Reason = h.forwardHTTP(w, r, ip, port, client.Name, host, &f)
	if f.Reason != "" {
		f.Trace("upstream", "fail", f.Reason)
	} else {
		f.Trace("upstream", "pass", "response received")
	}
}

func (h *Handler) recordFlow(item flow.Flow) {
	if h.Store == nil && h.Record == nil {
		return
	}
	h.recordMu.Lock()
	if h.recordClosed {
		h.recordMu.Unlock()
		return
	}
	if h.recordQueue == nil {
		h.recordQueue = make(chan flowRecordJob, h.recordQueueCapacity())
		h.recordContext, h.recordCancel = context.WithCancel(context.Background())
		log := h.Log
		if log == nil {
			log = slog.Default()
		}
		queue := h.recordQueue
		for range h.recordWorkerCount() {
			h.recordWG.Add(1)
			guard.Go(log, "record flows", func() {
				defer h.recordWG.Done()
				for job := range queue {
					h.recordFlowJob(log, job)
				}
			})
		}
	}
	queue := h.recordQueue
	recordContext := h.recordContext
	h.recordSubmitWG.Add(1)
	h.recordMu.Unlock()
	defer h.recordSubmitWG.Done()

	job := flowRecordJob{ctx: recordContext, item: item}
	dropped := false
	if item.Decision == "denied" {
		timer := time.NewTimer(recordDeniedEnqueueTimeout)
		select {
		case queue <- job:
			timer.Stop()
		case <-timer.C:
			dropped = true
		}
	} else {
		select {
		case queue <- job:
		default:
			dropped = true
		}
	}
	if dropped {
		h.recordDropped.Add(1)
		h.noteRecordDrop()
	}
}

func (h *Handler) noteRecordDrop() {
	now := time.Now().UnixNano()
	last := h.recordDropNoticeAt.Load()
	if last != 0 && now-last < int64(recordDropNoticeInterval) {
		return
	}
	if !h.recordDropNoticeAt.CompareAndSwap(last, now) {
		return
	}
	log := h.Log
	if log == nil {
		log = slog.Default()
	}
	log.Warn("flow records dropped under backpressure", "count", h.recordDropped.Load())
}

func (h *Handler) recordFlowJob(log *slog.Logger, job flowRecordJob) {
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Error("record flow panic", "panic", recovered)
		}
	}()
	item := job.item
	if h.Secrets != nil {
		item.Path = sanitizeText(h.Secrets, item.Path)
		item.Reason = sanitizeText(h.Secrets, item.Reason)
		for i := range item.PolicyTrace {
			item.PolicyTrace[i].Detail = sanitizeText(h.Secrets, item.PolicyTrace[i].Detail)
		}
	}
	if h.Store != nil {
		stored, err := h.Store.Add(job.ctx, item)
		if err != nil {
			log.Error("store flow", "host", item.Host, "err", err)
		} else {
			item = stored
		}
	}
	if h.Record != nil {
		h.Record(job.ctx, item)
	}
}

func (h *Handler) resolver() Resolver {
	if h.Resolver != nil {
		return h.Resolver
	}
	return PublicResolver{}
}

func (h *Handler) authenticate(r *http.Request) (*config.Client, bool) {
	if h.Policy == nil {
		return nil, false
	}
	raw := r.Header.Get("Proxy-Authorization")
	r.Header.Del("Proxy-Authorization")
	scheme, value, ok := strings.Cut(raw, " ")
	if !ok {
		return nil, false
	}
	switch strings.ToLower(scheme) {
	case "bearer":
		return h.Policy.Authenticate(strings.TrimSpace(value))
	case "basic":
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
		if err != nil {
			return nil, false
		}
		name, token, ok := strings.Cut(string(decoded), ":")
		if !ok {
			return nil, false
		}
		client, valid := h.Policy.Authenticate(token)
		return client, valid && client.Name == name
	default:
		return nil, false
	}
}

func requestTarget(r *http.Request) (string, int, string, error) {
	if r.Method == http.MethodConnect {
		host, port, err := splitAuthority(r.Host, 443)
		return host, port, "https", err
	}
	if r.URL == nil || !r.URL.IsAbs() || r.URL.Scheme != "http" || r.URL.User != nil {
		return "", 0, "", errors.New("proxy requests must use an absolute http URL")
	}
	host, port, err := splitAuthority(r.URL.Host, 80)
	if err != nil {
		return "", 0, "", err
	}
	headerHost, headerPort, err := splitAuthority(r.Host, 80)
	if err != nil || headerHost != host || headerPort != port {
		return "", 0, "", errors.New("request Host does not match the proxy target")
	}
	return host, port, "http", nil
}

func splitAuthority(authority string, defaultPort int) (string, int, error) {
	if authority == "" || strings.Contains(authority, "@") {
		return "", 0, errors.New("invalid destination authority")
	}
	host, portText, err := net.SplitHostPort(authority)
	if err != nil {
		if strings.Contains(authority, ":") {
			return "", 0, errors.New("destination port is required or malformed")
		}
		host, portText = authority, strconv.Itoa(defaultPort)
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if net.ParseIP(host) != nil {
		return "", 0, errors.New("direct IP destinations are not supported")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, errors.New("invalid destination port")
	}
	return host, port, nil
}

func (h *Handler) tunnel(w http.ResponseWriter, r *http.Request, ip netip.Addr, port int) (int, int64, int64, string) {
	upstream, err := h.dialContext()(r.Context(), "tcp", dialAddress(ip, port))
	if err != nil {
		http.Error(w, "upstream connection failed", http.StatusBadGateway)
		return http.StatusBadGateway, 0, 0, safeReason(err)
	}
	defer upstream.Close()

	client, rw, err := hijack(w)
	if err != nil {
		http.Error(w, "connection hijacking unavailable", http.StatusInternalServerError)
		return http.StatusInternalServerError, 0, 0, safeReason(err)
	}
	defer client.Close()
	clientActivity := newActivityConn(client, h.sessionIdleTimeout())
	upstreamActivity := newActivityConn(upstream, h.sessionIdleTimeout())
	stopContextWatcher := h.closeOnContext(r.Context(), "proxy tunnel context", client, upstream)
	defer stopContextWatcher()
	clientActivity.prepareWrite()
	if err := acknowledgeConnect(rw); err != nil {
		return http.StatusOK, 0, 0, safeReason(err)
	}

	type result struct {
		direction string
		n         int64
		err       error
	}
	results := make(chan result, 2)
	copyDirection := func(name string, dst io.Writer, src io.Reader) func() {
		return func() {
			copied := result{direction: name}
			defer func() { results <- copied }()
			copied.n, copied.err = io.Copy(dst, src)
		}
	}
	clientReader := activityReader{Reader: rw.Reader, conn: clientActivity}
	log := h.Log
	if log == nil {
		log = slog.Default()
	}
	guard.Go(log, "proxy tunnel upload", copyDirection("upload", upstreamActivity, clientReader))
	guard.Go(log, "proxy tunnel download", copyDirection("download", clientActivity, upstreamActivity))

	first := <-results
	_ = client.Close()
	_ = upstream.Close()
	second := <-results
	var sent, received int64
	for _, copied := range []result{first, second} {
		if copied.direction == "upload" {
			sent = copied.n
		} else {
			received = copied.n
		}
	}
	if first.err != nil && !errors.Is(first.err, net.ErrClosed) {
		return http.StatusOK, sent, received, safeReason(first.err)
	}
	return http.StatusOK, sent, received, ""
}

func (h *Handler) intercept(w http.ResponseWriter, outer *http.Request, identity *config.Client, host string, port int, sessionID string) (int, int64, int64, string) {
	client, rw, err := hijack(w)
	if err != nil {
		http.Error(w, "connection hijacking unavailable", http.StatusInternalServerError)
		return http.StatusInternalServerError, 0, 0, safeReason(err)
	}
	defer client.Close()
	clientActivity := newActivityConn(client, h.sessionIdleTimeout())
	stopContextWatcher := h.closeOnContext(outer.Context(), "intercepted session context", client)
	defer stopContextWatcher()
	clientActivity.prepareWrite()
	if err := acknowledgeConnect(rw); err != nil {
		return http.StatusOK, 0, 0, safeReason(err)
	}

	tlsConfig, err := h.Interceptor.TLSConfig(host)
	if err != nil {
		return http.StatusOK, 0, 0, safeReason(err)
	}
	buffered := &bufferedConn{Conn: clientActivity, reader: rw.Reader}
	tlsClient := tls.Server(buffered, tlsConfig)
	handshakeTimeout := h.DialTimeout
	if handshakeTimeout == 0 {
		handshakeTimeout = 10 * time.Second
	}
	handshakeCtx, cancel := context.WithTimeout(outer.Context(), handshakeTimeout)
	defer cancel()
	if err := tlsClient.HandshakeContext(handshakeCtx); err != nil {
		return http.StatusOK, 0, 0, safeReason(fmt.Errorf("intercept TLS handshake: %w", err))
	}
	defer tlsClient.Close()
	if tlsClient.ConnectionState().NegotiatedProtocol == "h2" {
		return h.interceptHTTP2(tlsClient, outer, identity, host, port, sessionID)
	}

	reader := bufio.NewReader(tlsClient)
	var totalSent, totalReceived int64
	for {
		requestStarted := time.Now()
		req, err := http.ReadRequest(reader)
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			return http.StatusOK, totalSent, totalReceived, ""
		}
		if err != nil {
			return http.StatusOK, totalSent, totalReceived, safeReason(fmt.Errorf("read intercepted request: %w", err))
		}
		req = req.WithContext(outer.Context())
		if strings.EqualFold(strings.TrimSpace(req.Header.Get("Expect")), "100-continue") {
			if _, err := io.WriteString(tlsClient, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
				return http.StatusOK, totalSent, totalReceived, safeReason(err)
			}
		}
		item := flow.Flow{
			SessionID:          sessionID,
			DownstreamProtocol: protocolLabel(req.ProtoMajor, req.ProtoMinor),
			StartedAt:          requestStarted,
			Client:             identity.Name,
			Method:             req.Method,
			Scheme:             "https",
			Host:               host,
			Port:               port,
			Path:               sanitizeText(h.Secrets, sanitizedPath(req.URL)),
			Mode:               "intercepted",
			Decision:           "denied",
		}
		status, sent, received, reason, closeConnection := h.handleInterceptedRequest(tlsClient, reader, req, identity, host, port, &item)
		item.Status, item.BytesSent, item.BytesReceived, item.Reason = status, sent, received, reason
		item.Duration = time.Since(requestStarted)
		totalSent += sent
		totalReceived += received
		h.recordFlow(item)
		if closeConnection {
			return http.StatusOK, totalSent, totalReceived, reason
		}
	}
}

func (h *Handler) handleInterceptedRequest(downstream io.Writer, downstreamReader *bufio.Reader, req *http.Request, identity *config.Client, host string, port int, item *flow.Flow) (int, int64, int64, string, bool) {
	if err := validateInterceptedRequest(req, host, port); err != nil {
		reason := safeReason(err)
		item.Trace("request-authority", "fail", reason)
		status := http.StatusMisdirectedRequest
		_ = writeSimpleResponse(downstream, req, status, reason)
		return status, 0, 0, reason, true
	}
	item.Trace("request-authority", "pass", "Host matches CONNECT authority and TLS SNI")
	if !identity.Allows(host, port) {
		reason := "destination is no longer allowed by client policy"
		item.Trace("destination-acl", "fail", reason)
		_ = writeSimpleResponse(downstream, req, http.StatusForbidden, reason)
		return http.StatusForbidden, 0, 0, reason, true
	}
	item.Trace("destination-acl", "pass", destinationPolicyDetail(identity))

	ip, err := h.resolver().Resolve(req.Context(), host)
	if err != nil {
		reason := safeReason(err)
		item.Trace("destination-ip", "fail", reason)
		_ = writeSimpleResponse(downstream, req, http.StatusForbidden, reason)
		return http.StatusForbidden, 0, 0, reason, true
	}
	item.DestinationIP = ip.String()
	item.Trace("destination-ip", "pass", ip.String())
	if isUnsupportedUpgrade(req) {
		reason := "unsupported HTTP upgrade"
		item.Trace("websocket-handshake", "fail", reason)
		_ = writeSimpleResponse(downstream, req, http.StatusBadRequest, reason)
		return http.StatusBadRequest, 0, 0, reason, true
	}
	if err := h.mediateRequest(req, identity.Name, host, true, item); err != nil {
		status := http.StatusBadRequest
		if mediationErr, ok := errors.AsType[*mediationError](err); ok {
			status = mediationErr.status
		}
		reason := safeReason(err)
		item.Trace("request-mediation", "fail", reason)
		_ = writeSimpleResponse(downstream, req, status, reason)
		return status, 0, 0, reason, true
	}
	item.Trace("secret-policy", "pass", secretTraceDetail(item.SecretNames))
	item.Trace("request-capture", "pass", "bounded sanitized capture prepared")
	item.Decision = "allowed"
	if isWebSocketUpgrade(req) {
		item.Mode = "websocket"
		return h.proxyWebSocket(downstream, downstreamReader, req, identity.Name, host, port, ip, item)
	}
	resp, sent, err := h.roundTrip(req, ip, port, "https")
	if err != nil {
		reason := h.sanitizedReason(err)
		item.Trace("upstream", "fail", reason)
		_ = writeSimpleResponse(downstream, req, http.StatusBadGateway, "upstream request failed")
		return http.StatusBadGateway, sent, 0, reason, true
	}
	defer resp.Body.Close()
	item.UpstreamProtocol = protocolLabel(resp.ProtoMajor, resp.ProtoMinor)
	item.Trace("upstream", "pass", "response received over "+item.UpstreamProtocol)
	if streaming, _ := shouldStreamResponse(req.Method, resp.StatusCode, resp.Header.Get("Content-Type")); streaming {
		resp.Close = req.Close || resp.Close
		encoding, sse, err := h.prepareStreamingResponse(resp, identity.Name, host, item)
		if err != nil {
			reason := safeReason(err)
			item.Trace("response-streaming", "fail", reason)
			_ = writeSimpleResponse(downstream, req, http.StatusBadGateway, reason)
			return http.StatusBadGateway, sent, 0, reason, true
		}
		if err := writeHTTP1StreamingHead(downstream, resp); err != nil {
			return resp.StatusCode, sent, 0, safeReason(err), true
		}
		chunked := httputil.NewChunkedWriter(downstream)
		received, streamErr := h.streamResponseBody(resp, chunked, nil, encoding, sse, identity.Name, host, item)
		closeErr := chunked.Close()
		item.ResponseSecretNames = mergeNames(item.ResponseSecretNames, h.scrubResponseMetadata(resp, identity.Name, host))
		trailerErr := resp.Trailer.Write(downstream)
		if trailerErr == nil {
			_, trailerErr = io.WriteString(downstream, "\r\n")
		}
		for _, candidate := range []error{streamErr, closeErr, trailerErr} {
			if candidate != nil {
				reason := safeReason(candidate)
				item.Trace("response-streaming", "fail", reason)
				return resp.StatusCode, sent, received, reason, true
			}
		}
		item.Trace("response-streaming", "pass", "records scrubbed and flushed incrementally")
		return resp.StatusCode, sent, received, "", req.Close || resp.Close
	}
	if err := h.mediateResponse(resp, identity.Name, host, item); err != nil {
		reason := safeReason(err)
		item.Trace("response-scrubbing", "fail", reason)
		_ = writeSimpleResponse(downstream, req, http.StatusBadGateway, reason)
		return http.StatusBadGateway, sent, 0, reason, true
	}
	item.Trace("response-scrubbing", "pass", secretTraceDetail(item.ResponseSecretNames))
	removeHopHeaders(resp.Header)
	resp.Close = req.Close
	var received int64
	resp.Body = &countingReadCloser{ReadCloser: resp.Body, n: &received}
	// The upstream transport may return HTTP/2, but the decrypted downstream
	// session is an HTTP/1.1 connection. Keep Response.Write's framing logic
	// (including Content-Length and trailers) while forcing its status line to
	// use the protocol version the downstream can parse.
	resp.Proto = "HTTP/1.1"
	resp.ProtoMajor = 1
	resp.ProtoMinor = 1
	if err := resp.Write(downstream); err != nil {
		return resp.StatusCode, sent, received, safeReason(err), true
	}
	return resp.StatusCode, sent, received, "", req.Close || resp.Close
}

func validateInterceptedRequest(req *http.Request, host string, port int) error {
	if req.Method == http.MethodConnect {
		return errors.New("nested CONNECT is not allowed")
	}
	headerHost, headerPort, err := splitAuthority(req.Host, 443)
	if err != nil || headerHost != host || headerPort != port {
		return errors.New("intercepted Host does not match CONNECT authority")
	}
	if req.URL == nil || req.URL.User != nil {
		return errors.New("invalid intercepted request URL")
	}
	if req.URL.IsAbs() {
		urlHost, urlPort, err := splitAuthority(req.URL.Host, 443)
		if err != nil || req.URL.Scheme != "https" || urlHost != host || urlPort != port {
			return errors.New("intercepted URL does not match CONNECT authority")
		}
	}
	return nil
}

func (h *Handler) forwardHTTP(w http.ResponseWriter, r *http.Request, ip netip.Addr, port int, client, host string, item *flow.Flow) (int, int64, int64, string) {
	resp, sent, err := h.roundTrip(r, ip, port, "http")
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return http.StatusBadGateway, sent, 0, safeReason(err)
	}
	defer resp.Body.Close()
	item.UpstreamProtocol = protocolLabel(resp.ProtoMajor, resp.ProtoMinor)
	if streaming, _ := shouldStreamResponse(r.Method, resp.StatusCode, resp.Header.Get("Content-Type")); streaming {
		encoding, sse, err := h.prepareStreamingResponse(resp, client, host, item)
		if err != nil {
			reason := safeReason(err)
			item.Trace("response-streaming", "fail", reason)
			http.Error(w, "upstream response failed mediation", http.StatusBadGateway)
			return http.StatusBadGateway, sent, 0, reason
		}
		copyStreamingResponseHeaders(w.Header(), resp)
		w.WriteHeader(resp.StatusCode)
		received, streamErr := h.streamResponseBody(resp, w, http.NewResponseController(w).Flush, encoding, sse, client, host, item)
		item.ResponseSecretNames = mergeNames(item.ResponseSecretNames, h.scrubResponseMetadata(resp, client, host))
		copyResponseTrailers(w.Header(), resp)
		if streamErr != nil {
			reason := safeReason(streamErr)
			item.Trace("response-streaming", "fail", reason)
			return resp.StatusCode, sent, received, reason
		}
		item.Trace("response-streaming", "pass", "records scrubbed and flushed incrementally")
		return resp.StatusCode, sent, received, ""
	}
	if err := h.mediateResponse(resp, client, host, item); err != nil {
		reason := safeReason(err)
		item.Trace("response-scrubbing", "fail", reason)
		http.Error(w, "upstream response failed mediation", http.StatusBadGateway)
		return http.StatusBadGateway, sent, 0, reason
	}
	item.Trace("response-scrubbing", "pass", secretTraceDetail(item.ResponseSecretNames))
	removeHopHeaders(resp.Header)
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	received, copyErr := io.Copy(w, resp.Body)
	if copyErr != nil {
		return resp.StatusCode, sent, received, safeReason(copyErr)
	}
	return resp.StatusCode, sent, received, ""
}

func (h *Handler) roundTrip(r *http.Request, ip netip.Addr, port int, scheme string) (*http.Response, int64, error) {
	var sent int64
	out := r.Clone(r.Context())
	if out.Body != nil {
		out.Body = &countingReadCloser{ReadCloser: out.Body, n: &sent}
	}
	out.RequestURI = ""
	out.URL.Scheme = scheme
	out.URL.Host = destinationAuthority(out.Host, port, scheme)
	removeHopHeaders(out.Header)
	out.Header.Del("Proxy-Connection")
	out.Close = false

	cached := h.acquireUpstreamTransport(scheme, out.URL.Hostname(), ip, port)
	if cached == nil {
		return nil, sent, errHandlerClosed
	}
	resp, err := cached.transport.RoundTrip(out)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		h.releaseUpstreamTransport(cached)
		return resp, sent, err
	}
	if resp == nil || resp.Body == nil {
		h.releaseUpstreamTransport(cached)
		return nil, sent, errors.New("upstream transport returned a response without a body")
	}
	resp.Body = &trackedResponseBody{
		ReadCloser: resp.Body,
		release:    func() { h.releaseUpstreamTransport(cached) },
	}
	return resp, sent, nil
}

func (h *Handler) dialContext() func(context.Context, string, string) (net.Conn, error) {
	if h.DialContext != nil {
		return h.DialContext
	}
	return defaultDialer(h.dialTimeout())
}

func hijack(w http.ResponseWriter) (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w).Hijack()
}

func acknowledgeConnect(rw *bufio.ReadWriter) error {
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}
	return rw.Flush()
}

func writeSimpleResponse(w io.Writer, req *http.Request, status int, message string) error {
	body := message + "\n"
	resp := &http.Response{
		StatusCode:    status,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
		Request:       req,
	}
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp.Header.Set("Cache-Control", "no-store")
	return resp.Write(w)
}

func protocolLabel(major, minor int) string {
	if major == 2 {
		return "h2"
	}
	if major == 1 && minor == 1 {
		return "http/1.1"
	}
	if major == 1 {
		return "http/1.0"
	}
	return "unknown"
}

func destinationAuthority(requestHost string, port int, scheme string) string {
	host, _, err := net.SplitHostPort(requestHost)
	if err != nil {
		host = strings.TrimSuffix(requestHost, ".")
	}
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func sanitizedPath(u *url.URL) string {
	if u == nil {
		return ""
	}
	path := u.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

type activityConn struct {
	net.Conn
	idle time.Duration
}

func newActivityConn(conn net.Conn, idle time.Duration) *activityConn {
	return &activityConn{Conn: conn, idle: idle}
}

func (c *activityConn) prepareRead() {
	if c.idle > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	}
}

func (c *activityConn) prepareWrite() {
	if c.idle > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	}
}

func (c *activityConn) Read(p []byte) (int, error) {
	c.prepareRead()
	return c.Conn.Read(p)
}

func (c *activityConn) Write(p []byte) (int, error) {
	c.prepareWrite()
	return c.Conn.Write(p)
}

type activityReader struct {
	io.Reader
	conn *activityConn
}

func (r activityReader) Read(p []byte) (int, error) {
	r.conn.prepareRead()
	return r.Reader.Read(p)
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	if deadlineConn, ok := c.Conn.(interface{ prepareRead() }); ok {
		deadlineConn.prepareRead()
	}
	return c.reader.Read(p)
}

type countingReadCloser struct {
	io.ReadCloser
	n *int64
}

func (r *countingReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	*r.n += int64(n)
	return n, err
}

func removeHopHeaders(header http.Header) {
	for value := range strings.SplitSeq(header.Get("Connection"), ",") {
		header.Del(strings.TrimSpace(value))
	}
	for _, name := range []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func (h *Handler) closeOnContext(ctx context.Context, name string, closers ...io.Closer) func() {
	stop := make(chan struct{})
	log := h.Log
	if log == nil {
		log = slog.Default()
	}
	guard.Go(log, name, func() {
		select {
		case <-ctx.Done():
			for _, closer := range closers {
				_ = closer.Close()
			}
		case <-stop:
		}
	})
	return func() { close(stop) }
}

func newSessionID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func destinationPolicyDetail(client *config.Client) string {
	if client.ObserveAllPublicHosts {
		return "all-public-host observation policy allowed destination"
	}
	return "client allowlist allowed destination"
}

func (h *Handler) sanitizedReason(err error) string {
	reason := safeReason(err)
	return sanitizeText(h.Secrets, reason)
}

func secretTraceDetail(names []string) string {
	if len(names) == 0 {
		return "no placeholders present"
	}
	return "substituted: " + strings.Join(names, ", ")
}

func safeReason(err error) string {
	if err == nil {
		return ""
	}
	reason := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, err.Error())
	if len(reason) > maxErrorReason {
		return reason[:maxErrorReason] + "…"
	}
	return reason
}
