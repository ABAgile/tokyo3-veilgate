package proxy

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/abagile/tokyo3-base/guard"

	"github.com/abagile/veilgate/internal/config"
	"github.com/abagile/veilgate/internal/flow"
)

// handling is how an allowed CONNECT destination is carried.
type handling int

const (
	// handlingOpaque relays TCP bytes without terminating TLS.
	handlingOpaque handling = iota
	// handlingInspect terminates TLS and enforces policy on the request line
	// and headers, but streams bodies without buffering or rewriting them.
	handlingInspect
	// handlingFull terminates TLS and fully mediates requests and responses.
	handlingFull
)

// methodOverrideHeaders let a request change its effective method upstream.
// They would defeat method rules, so restricted hosts refuse them.
var methodOverrideHeaders = []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"}

// handlingFor selects how host is carried. allowed_rules are only enforceable
// on intercepted traffic, so a rule-bearing host is never an opaque tunnel;
// rules guarantee interception but never reduce it. Brokered and
// intercept_hosts destinations are fully mediated, inspect_hosts destinations
// are inspected, an opaque_hosts or intercept_mode "opaque" destination that
// has rules is inspected rather than buffered, and the remainder follows
// intercept_mode: "intercept" mediates fully, "opaque" leaves it opaque, and
// "inspect" inspects it.
func (h *Handler) handlingFor(client *config.Client, host string) handling {
	rules := client.HasRulesFor(host)
	opaque := client.UsesOpaqueTunnel(host)
	if opaque && !rules {
		return handlingOpaque
	}
	scoper, ok := h.Secrets.(hostScoper)
	if client.InterceptsListedHost(host) || ok && scoper.ScopesHost(client.Name, host) {
		return handlingFull
	}
	if client.InspectsHost(host) || opaque {
		return handlingInspect
	}
	switch client.InterceptMode {
	case config.ModeOpaque:
		if rules {
			return handlingInspect
		}
		return handlingOpaque
	case config.ModeInspect:
		return handlingInspect
	}
	return handlingFull
}

// requestRulePath returns the decoded request path for rule matching. Paths
// that could be read differently by this check and the origin (dot segments,
// encoded separators, control characters, double encoding) are refused.
func requestRulePath(u *url.URL) (string, error) {
	if u == nil {
		return "", errors.New("request has no URL")
	}
	escaped := strings.ToLower(u.EscapedPath())
	if strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") || strings.Contains(escaped, `\`) {
		return "", errors.New("request path contains an encoded or backslash separator")
	}
	path := u.Path
	if !strings.HasPrefix(path, "/") {
		return "", errors.New("request path is not absolute")
	}
	for _, character := range path {
		if character < 0x20 || character == 0x7f {
			return "", errors.New("request path contains a control character")
		}
	}
	lowered := strings.ToLower(path)
	if strings.Contains(lowered, "%2e") || strings.Contains(lowered, "%2f") || strings.Contains(lowered, "%5c") {
		return "", errors.New("request path is double-encoded")
	}
	for segment := range strings.SplitSeq(path, "/") {
		if segment == "." || segment == ".." {
			return "", errors.New("request path contains dot segments")
		}
	}
	return path, nil
}

// enforceRequestRules applies client's allowed_rules to req. A host handled as
// inspect-only that has no rule gets the default read-only policy: GET and
// HEAD without a request body. Any explicit rule for the host replaces that
// default. Other hosts are unaffected.
func (h *Handler) enforceRequestRules(req *http.Request, client *config.Client, host string, item *flow.Flow) error {
	restricted := client.HasRulesFor(host)
	readOnly := !restricted && h.handlingFor(client, host) == handlingInspect
	if !restricted && !readOnly {
		return nil
	}
	deny := func(status int, err error) error {
		item.Trace("request-rules", "fail", safeReason(err))
		return &mediationError{status, err}
	}
	for _, name := range methodOverrideHeaders {
		if req.Header.Get(name) != "" {
			return deny(http.StatusForbidden, fmt.Errorf("%s is not allowed on a restricted host", name))
		}
	}
	if readOnly {
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			return deny(http.StatusForbidden, errors.New("denied by the default read-only policy for inspect_hosts; add an allowed_rules entry to permit "+req.Method))
		}
		if req.Body != nil && req.Body != http.NoBody && req.ContentLength != 0 {
			return deny(http.StatusRequestEntityTooLarge, errors.New("request body is not allowed by the default read-only policy for inspect_hosts"))
		}
		item.Trace("request-rules", "pass", "default read-only policy for inspect_hosts")
		return nil
	}
	// The path only matters to rules with path_prefixes. A path that cannot be
	// read unambiguously (encoded separators, dot segments, ...) matches no
	// prefix, but still satisfies rules that do not constrain the path, so
	// ordinary encoded names such as npm's /@scope%2fname stay reachable.
	path, pathErr := requestRulePath(req.URL)
	if pathErr != nil {
		path = ""
	}
	rule, ok := client.MatchRule(host, req.Method, path)
	if !ok {
		if pathErr != nil {
			return deny(http.StatusForbidden, fmt.Errorf("request is not permitted by allowed_rules: %w", pathErr))
		}
		return deny(http.StatusForbidden, errors.New("request is not permitted by allowed_rules"))
	}
	if limit := rule.MaxRequestBytes; limit > 0 && req.Body != nil && req.Body != http.NoBody {
		if req.ContentLength > limit {
			return deny(http.StatusRequestEntityTooLarge, errors.New("request body exceeds max_request_bytes"))
		}
		req.Body = &limitedBody{ReadCloser: req.Body, remaining: limit}
	}
	item.Trace("request-rules", "pass", "method and path permitted by allowed_rules")
	return nil
}

// limitedBody fails once more than the permitted number of bytes is read, so a
// chunked or HTTP/2 upload with no declared length cannot exceed the cap.
type limitedBody struct {
	io.ReadCloser
	remaining int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.remaining < 0 {
		return 0, errBodyLimit
	}
	if int64(len(p)) > b.remaining+1 {
		p = p[:b.remaining+1]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	if b.remaining < 0 {
		return max(n+int(b.remaining), 0), errBodyLimit
	}
	return n, err
}

var errBodyLimit = errors.New("request body exceeds max_request_bytes")

// inspectRequest applies the header-level policy of mediateRequest without
// touching the body: placeholder guards, query handling, and header capture.
func (h *Handler) inspectRequest(req *http.Request, client, host string, item *flow.Flow) error {
	names, _, err := h.mediateRequestHead(req, client, host, true, item)
	if err != nil {
		return err
	}
	item.SecretNames = names
	headers, truncated := captureHeaders(req.Header, req.Host, h.Secrets, h.captureLimit())
	item.Capture.RequestHeaders = headers
	item.Capture.Truncated = item.Capture.Truncated || truncated
	return nil
}

const (
	maxDrainedRequestBody = 16 << 20
	drainRequestBodyTime  = 5 * time.Second
)

// drainRequestBody discards the unread remainder of a request body before the
// connection is closed after an early response (a denial, for example).
// Closing a socket that still holds unread data makes the kernel send a reset,
// which can destroy the response before the client reads it, so a client
// uploading a large body would see a write error instead of the status. The
// drain is bounded in size and time, so a client that keeps sending past it is
// simply disconnected; the caller's close unblocks a drain still reading.
func (h *Handler) drainRequestBody(req *http.Request) {
	body := req.Body
	if body == nil || body == http.NoBody {
		return
	}
	if capped, ok := body.(*limitedBody); ok {
		body = capped.ReadCloser
	}
	log := h.Log
	if log == nil {
		log = slog.Default()
	}
	done := make(chan struct{})
	guard.Go(log, "proxy drain request body", func() {
		defer close(done)
		_, _ = io.CopyN(io.Discard, body, maxDrainedRequestBody)
	})
	timer := time.NewTimer(drainRequestBodyTime)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
}

// frameStreamedResponse gives a body of unknown length, typical of an HTTP/2
// upstream, a delimiter the HTTP/1.1 downstream can use. Without one,
// Response.Write ends the body by closing the connection on its own copy of the
// response, so the caller would keep the connection open and the client would
// wait for the end of a body that was already fully sent.
func frameStreamedResponse(req *http.Request, resp *http.Response) {
	if resp.ContentLength >= 0 || len(resp.TransferEncoding) > 0 || resp.Close || !responseHasBody(resp) {
		return
	}
	if req.ProtoAtLeast(1, 1) {
		resp.TransferEncoding = []string{"chunked"}
		return
	}
	resp.Close = true
}

// inspectResponse records response headers; the body is left to stream.
func (h *Handler) inspectResponse(resp *http.Response, client, host string, item *flow.Flow) {
	item.ResponseSecretNames = h.scrubResponseMetadata(resp, client, host)
	headers, truncated := captureHeaders(resp.Header, "", h.Secrets, h.captureLimit())
	item.Capture.ResponseHeaders = headers
	item.Capture.Truncated = item.Capture.Truncated || truncated
}

// admitInterceptedRequest enforces request rules and then mediates the request
// at the depth selected for its host.
func (h *Handler) admitInterceptedRequest(req *http.Request, current *config.Client, client, host string, inspect bool, item *flow.Flow) error {
	if err := h.enforceRequestRules(req, current, host, item); err != nil {
		return err
	}
	if inspect {
		return h.inspectRequest(req, client, host, item)
	}
	return h.mediateRequest(req, client, host, true, item)
}
