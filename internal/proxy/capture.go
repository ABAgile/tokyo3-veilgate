package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/abagile/veilgate/internal/flow"
)

const (
	defaultCaptureLimit   int64 = 1 << 20
	defaultMediationLimit int64 = 4 << 20
)

var errCaptureLimit = errors.New("traffic payload exceeds capture limit")

type mediationError struct {
	status int
	err    error
}

func (e *mediationError) Error() string { return e.err.Error() }
func (e *mediationError) Unwrap() error { return e.err }

func (h *Handler) mediationLimit() int64 {
	if h.MediationLimit > 0 {
		return h.MediationLimit
	}
	return defaultMediationLimit
}

func (h *Handler) captureLimit() int64 {
	if h.CaptureLimit > 0 {
		return h.CaptureLimit
	}
	return defaultCaptureLimit
}

func (h *Handler) mediateRequest(req *http.Request, client, host string, secure bool, item *flow.Flow) error {
	redactions := sensitiveHeaderValues(req.Header)
	if expectation := strings.TrimSpace(req.Header.Get("Expect")); expectation != "" {
		if !strings.EqualFold(expectation, "100-continue") {
			return &mediationError{http.StatusExpectationFailed, errors.New("unsupported request expectation")}
		}
		req.Header.Del("Expect")
	}
	if req.URL != nil && int64(len(req.URL.RawQuery)) > h.mediationLimit() {
		return &mediationError{http.StatusRequestURITooLong, errors.New("query string exceeds mediation limit")}
	}
	if h.Secrets != nil && req.URL != nil && h.Secrets.ContainsPlaceholder([]byte(req.URL.EscapedPath())) {
		return &mediationError{http.StatusForbidden, errors.New("secret placeholders are not allowed in URL paths")}
	}
	query, err := captureQuery(req.URL, h.Secrets, redactions)
	if err != nil {
		return &mediationError{http.StatusBadRequest, err}
	}
	if int64(len(query)) > h.captureLimit() {
		query = query[:h.captureLimit()]
		item.Capture.Truncated = true
	}
	item.Capture.Query = query

	var names []string
	if h.Secrets != nil {
		headerNames, err := h.Secrets.Apply(req, client, host, secure)
		if err != nil {
			return &mediationError{http.StatusForbidden, err}
		}
		queryNames, err := h.Secrets.SubstituteQuery(req.URL, client, host, secure)
		if err != nil {
			return &mediationError{http.StatusForbidden, err}
		}
		if req.URL != nil && int64(len(req.URL.RawQuery)) > h.mediationLimit() {
			return &mediationError{http.StatusRequestURITooLong, errors.New("substituted query string exceeds mediation limit")}
		}
		names = mergeNames(headerNames, queryNames)
		redactions = append(redactions, sensitiveHeaderValues(req.Header)...)
	}

	if req.Body == nil || req.Body == http.NoBody {
		item.SecretNames = names
		item.Capture.RequestHeaders, item.Capture.Truncated = captureHeaders(req.Header, req.Host, h.Secrets, h.captureLimit())
		return nil
	}
	encoding, err := contentEncoding(req.Header)
	if err != nil {
		return &mediationError{http.StatusUnsupportedMediaType, err}
	}
	wireBody, err := readBounded(req.Body, h.mediationLimit())
	_ = req.Body.Close()
	if err != nil {
		return &mediationError{http.StatusRequestEntityTooLarge, errors.New("encoded request body exceeds mediation limit")}
	}
	body, err := decodeHTTPBody(wireBody, encoding, h.mediationLimit())
	if err != nil {
		return &mediationError{http.StatusRequestEntityTooLarge, err}
	}
	contentType := req.Header.Get("Content-Type")
	transformed, bodyNames, supported, err := h.substituteBody(contentType, body, client, host, secure)
	if err != nil {
		return &mediationError{http.StatusForbidden, err}
	}
	encoded, err := encodeHTTPBody(transformed, encoding, h.mediationLimit())
	if err != nil {
		return &mediationError{http.StatusRequestEntityTooLarge, err}
	}
	names = mergeNames(names, bodyNames)
	if h.Secrets != nil && len(req.Trailer) > 0 {
		trailerRequest := &http.Request{Header: req.Trailer}
		trailerNames, err := h.Secrets.Apply(trailerRequest, client, host, secure)
		if err != nil {
			return &mediationError{http.StatusForbidden, err}
		}
		names = mergeNames(names, trailerNames)
		redactions = append(redactions, sensitiveHeaderValues(req.Trailer)...)
	}
	item.SecretNames = names
	var bodyTruncated bool
	item.Capture.RequestBody, bodyTruncated = capturePayload(contentType, transformed, supported, h.Secrets, redactions, h.captureLimit())
	item.Capture.Truncated = item.Capture.Truncated || bodyTruncated
	if len(bodyNames) > 0 {
		removeIntegrityHeaders(req.Header)
	}
	replaceRequestBody(req, encoded)
	item.Capture.RequestHeaders, item.Capture.Truncated = captureHeaders(req.Header, req.Host, h.Secrets, h.captureLimit())
	return nil
}

func (h *Handler) substituteBody(contentType string, body []byte, client, host string, secure bool) ([]byte, []string, bool, error) {
	// Captured media types are validated here rather than as a side effect of
	// substitution, so the guarantee holds whether or not a broker rewrites the
	// body for this destination.
	supported := requestCaptureMediaType(contentType)
	if supported {
		if err := validateCapturedBody(contentType, body); err != nil {
			return nil, nil, true, err
		}
	}
	if h.Secrets != nil {
		transformed, names, brokerSupported, err := h.Secrets.SubstituteBody(contentType, body, client, host, secure)
		return transformed, names, supported || brokerSupported, err
	}
	return body, nil, supported, nil
}

func (h *Handler) mediateResponse(resp *http.Response, client, host string, item *flow.Flow) error {
	if !responseHasBody(resp) {
		item.ResponseSecretNames = h.scrubResponseMetadata(resp, client, host)
		item.Capture.ResponseHeaders, item.Capture.Truncated = captureHeaders(resp.Header, "", h.Secrets, h.captureLimit())
		return nil
	}
	encoding, err := contentEncoding(resp.Header)
	if err != nil {
		return &mediationError{http.StatusBadGateway, err}
	}
	wireBody, err := readBounded(resp.Body, h.mediationLimit())
	_ = resp.Body.Close()
	if err != nil {
		return &mediationError{http.StatusBadGateway, errors.New("encoded upstream response exceeds mediation limit")}
	}
	body, err := decodeHTTPBody(wireBody, encoding, h.mediationLimit())
	if err != nil {
		return &mediationError{http.StatusBadGateway, err}
	}
	item.BytesReceivedDecoded = int64(len(body))
	var names []string
	if h.OAuth != nil && resp.Request != nil {
		transformed, oauthNames, err := h.OAuth.ObserveTokenResponse(resp.Request, resp, body, client, host)
		if err != nil {
			return &mediationError{http.StatusBadGateway, err}
		}
		body = transformed
		names = mergeNames(names, oauthNames)
	}
	names = mergeNames(names, h.scrubResponseMetadata(resp, client, host))
	var bodyNames []string
	if h.Secrets != nil {
		body, bodyNames = h.Secrets.Scrub(body, client, host)
		names = mergeNames(names, bodyNames)
	}
	encoded, err := encodeHTTPBody(body, encoding, h.mediationLimit())
	if err != nil {
		return &mediationError{http.StatusBadGateway, err}
	}
	if len(bodyNames) > 0 {
		removeIntegrityHeaders(resp.Header)
		resp.Header.Del("ETag")
	}
	item.ResponseSecretNames = names
	var redactions [][]byte
	if resp.Request != nil {
		redactions = sensitiveHeaderValues(resp.Request.Header)
	}
	responseContentType := resp.Header.Get("Content-Type")
	if strings.TrimSpace(responseContentType) == "" {
		responseContentType = inferResponseContentType(body)
	}
	var bodyTruncated bool
	item.Capture.ResponseBody, bodyTruncated = capturePayload(responseContentType, body, responseCaptureMediaType(responseContentType), h.Secrets, redactions, h.captureLimit())
	item.Capture.Truncated = item.Capture.Truncated || bodyTruncated
	replaceResponseBody(resp, encoded)
	var truncated bool
	item.Capture.ResponseHeaders, truncated = captureHeaders(resp.Header, "", h.Secrets, h.captureLimit())
	item.Capture.Truncated = item.Capture.Truncated || truncated
	return nil
}

func (h *Handler) scrubResponseMetadata(resp *http.Response, client, host string) []string {
	var names []string
	if h.Secrets == nil {
		return names
	}
	for _, header := range []http.Header{resp.Header, resp.Trailer} {
		for name, values := range header {
			for i, value := range values {
				scrubbed, found := h.Secrets.Scrub([]byte(value), client, host)
				values[i] = string(scrubbed)
				names = mergeNames(names, found)
			}
			header[name] = values
		}
	}
	status, found := h.Secrets.Scrub([]byte(resp.Status), client, host)
	resp.Status = string(status)
	return mergeNames(names, found)
}

func responseHasBody(resp *http.Response) bool {
	if resp.Request != nil && resp.Request.Method == http.MethodHead {
		return false
	}
	return resp.StatusCode < 100 || resp.StatusCode >= 200 && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	if limit < 1 {
		return nil, errCaptureLimit
	}
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errCaptureLimit
	}
	return data, nil
}

func replaceResponseBody(resp *http.Response, body []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if len(resp.Trailer) > 0 {
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
		resp.TransferEncoding = []string{"chunked"}
		return
	}
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	resp.Header.Del("Transfer-Encoding")
	resp.TransferEncoding = nil
}

func replaceRequestBody(req *http.Request, body []byte) {
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	if len(req.Trailer) > 0 {
		req.ContentLength = -1
		req.Header.Del("Content-Length")
		req.TransferEncoding = []string{"chunked"}
		return
	}
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	req.Header.Del("Transfer-Encoding")
	req.TransferEncoding = nil
}

func captureQuery(u *url.URL, broker SecretBroker, redactions [][]byte) (string, error) {
	if u == nil || u.RawQuery == "" {
		return "", nil
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", errors.New("query string is malformed")
	}
	for name, entries := range values {
		cleanName := string(sanitizeCaptureBytes(broker, []byte(name), redactions))
		for i, value := range entries {
			entries[i] = string(sanitizeCaptureBytes(broker, []byte(value), redactions))
		}
		if cleanName != name {
			delete(values, name)
			values[cleanName] = append(values[cleanName], entries...)
		}
	}
	encoded := values.Encode()
	encoded = strings.ReplaceAll(encoded, "%5Bsecret%3A", "[secret:")
	encoded = strings.ReplaceAll(encoded, "%5D", "]")
	return encoded, nil
}

func capturePayload(contentType string, body []byte, supported bool, broker SecretBroker, redactions [][]byte, limit int64) (*flow.PayloadCapture, bool) {
	capture := &flow.PayloadCapture{ContentType: string(sanitizeCaptureBytes(broker, []byte(contentType), redactions)), Omitted: !supported}
	if !supported {
		return capture, false
	}
	clean := sanitizeCaptureBytes(broker, body, redactions)
	truncated := int64(len(clean)) > limit
	if truncated {
		clean = clean[:limit]
		for len(clean) > 0 && !utf8.Valid(clean) {
			clean = clean[:len(clean)-1]
		}
	}
	capture.Text = string(clean)
	capture.Truncated = truncated
	return capture, truncated
}

func validateCapturedBody(contentType string, body []byte) error {
	mediaType := mediaType(contentType)
	if mediaType == "application/json" || strings.HasSuffix(mediaType, "+json") {
		if !jsonValidOne(body) {
			return errors.New("JSON request body is malformed")
		}
	}
	if mediaType == "application/x-www-form-urlencoded" {
		if _, err := url.ParseQuery(string(body)); err != nil {
			return errors.New("form request body is malformed")
		}
	}
	return nil
}

func jsonValidOne(body []byte) bool {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return false
	}
	return errors.Is(decoder.Decode(new(any)), io.EOF)
}

func requestCaptureMediaType(contentType string) bool {
	value := mediaType(contentType)
	return value == "text/event-stream" || value == "application/json" || strings.HasSuffix(value, "+json") || value == "application/x-www-form-urlencoded"
}

func responseCaptureMediaType(contentType string) bool {
	value := mediaType(contentType)
	return strings.HasPrefix(value, "text/") || value == "application/json" || strings.HasSuffix(value, "+json") ||
		value == "application/x-www-form-urlencoded" || value == "application/xml" || strings.HasSuffix(value, "+xml") ||
		value == "application/javascript"
}

func inferResponseContentType(body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "data:") || strings.Contains(trimmed, "\ndata:") {
		return "text/event-stream"
	}
	if jsonValidOne(body) {
		return "application/json"
	}
	return ""
}

func mediaType(contentType string) string {
	value, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ""
	}
	return strings.ToLower(value)
}

func sanitizeCaptureBytes(broker SecretBroker, value []byte, redactions [][]byte) []byte {
	return redactCaptureValues(sanitizeBytes(broker, value), redactions)
}

func sanitizeText(broker SecretBroker, value string) string {
	return string(sanitizeBytes(broker, []byte(value)))
}

func sanitizeBytes(broker SecretBroker, value []byte) []byte {
	if broker == nil {
		return append([]byte(nil), value...)
	}
	return broker.Sanitize(value)
}

func mergeNames(groups ...[]string) []string {
	var names []string
	for _, group := range groups {
		for _, name := range group {
			if !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	slices.Sort(names)
	return names
}
