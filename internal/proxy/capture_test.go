package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abagile/veilgate/internal/flow"
	"github.com/abagile/veilgate/internal/oauth"
	"github.com/abagile/veilgate/internal/secret"
)

func proxyTestBroker(t *testing.T) *secret.Broker {
	t.Helper()
	broker, err := secret.New(secret.File{Secrets: []secret.Definition{{
		Name: "api_key", ValueEnv: "TEST_API_KEY", Placeholder: testPlaceholder,
		Clients: []string{"agent"}, AllowedHosts: []string{"allowed.example"},
	}}}, func(string) (string, bool) { return "real-api-key", true })
	if err != nil {
		t.Fatal(err)
	}
	return broker
}

func TestMediateResponseVirtualizesOAuthTokensBeforeCapture(t *testing.T) {
	authPath := filepath.Join(t.TempDir(), "auth.json")
	broker, err := oauth.New(oauth.File{Brokers: []oauth.Definition{{
		Name: "example", Clients: []string{"agent"}, IssuerHost: "login.example.com",
		TokenPath: "/oauth/token", APIHosts: []string{"api.example.com"},
	}}}, authPath)
	if err != nil {
		t.Fatal(err)
	}
	tokenURL, _ := url.Parse("https://login.example.com/oauth/token")
	request := &http.Request{Method: http.MethodPost, URL: tokenURL, Host: "login.example.com"}
	resp := &http.Response{
		StatusCode: http.StatusOK, Status: "200 OK",
		Header: http.Header{
			"Content-Type":    {"application/json"},
			"X-Echoed-Access": {"real-access"},
		},
		Body:    io.NopCloser(strings.NewReader(`{"access_token":"real-access","refresh_token":"real-refresh","echo":"real-access","expires_in":3600}`)),
		Request: request,
	}
	item := &flow.Flow{}
	h := &Handler{Secrets: broker, OAuth: broker, CaptureLimit: 4096, MediationLimit: 4096}
	if err := h.mediateResponse(resp, "agent", "login.example.com", item); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "real-access") || strings.Contains(string(body), "real-refresh") || resp.Header.Get("X-Echoed-Access") == "real-access" || !strings.Contains(string(body), "VEILGATED_SECRET_OAUTH_ACCESS_") {
		t.Fatalf("OAuth response = %q header = %q", body, resp.Header.Get("X-Echoed-Access"))
	}
	if item.Capture.ResponseBody == nil || !strings.Contains(item.Capture.ResponseBody.Text, "[secret:oauth_example_access_token]") || len(item.ResponseSecretNames) != 2 {
		t.Fatalf("OAuth capture = %#v response names = %#v", item.Capture.ResponseBody, item.ResponseSecretNames)
	}
	apiRequest, _ := http.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	apiRequest.Header.Set("Authorization", "Bearer "+extractJSONString(t, body, "access_token"))
	if _, err := broker.Apply(apiRequest, "agent", "api.example.com", true); err != nil || apiRequest.Header.Get("Authorization") != "Bearer real-access" {
		t.Fatalf("virtual API request = %q err = %v", apiRequest.Header.Get("Authorization"), err)
	}
}

func TestRequestCaptureRetainsEventStreamBody(t *testing.T) {
	body := "data: {\"message\":\"first line\\nsecond line\"}\n\ndata: {\"message\":\"third line\\nfourth line\"}\n\n"
	req := &http.Request{
		Method: http.MethodPost, Host: "allowed.example",
		Header: http.Header{"Content-Type": {"text/event-stream"}},
		Body:   io.NopCloser(strings.NewReader(body)),
	}
	item := &flow.Flow{}
	if err := (&Handler{Secrets: proxyTestBroker(t), CaptureLimit: 4096, MediationLimit: 4096}).mediateRequest(req, "agent", "allowed.example", true, item); err != nil {
		t.Fatal(err)
	}
	if item.Capture.RequestBody == nil || item.Capture.RequestBody.Omitted || item.Capture.RequestBody.Text != body {
		t.Fatalf("request capture = %#v", item.Capture.RequestBody)
	}
}

func TestSubstituteBodyValidatesCapturedBodiesWithBrokerConfigured(t *testing.T) {
	broker, err := oauth.New(oauth.File{Brokers: []oauth.Definition{{
		Name: "example", Clients: []string{"agent"}, IssuerHost: "login.example.com",
		TokenPath: "/oauth/token", APIHosts: []string{"api.example.com"},
	}}}, filepath.Join(t.TempDir(), "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Secrets: broker, OAuth: broker, CaptureLimit: 4096, MediationLimit: 4096}
	// The OAuth broker does not rewrite bodies for API hosts, so validation must
	// come from the proxy rather than as a side effect of substitution.
	if _, _, _, err := h.substituteBody("application/json", []byte(`{"prompt":`), "agent", "api.example.com", true); err == nil {
		t.Fatal("malformed JSON body accepted")
	}
	if _, _, _, err := h.substituteBody("application/json", []byte(`{"prompt":"hi"}`), "agent", "api.example.com", true); err != nil {
		t.Fatalf("well-formed JSON body rejected: %v", err)
	}
}

func extractJSONString(t *testing.T, body []byte, field string) string {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	var value string
	if err := json.Unmarshal(fields[field], &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestMediateResponseScrubsBeforeCaptureAndDelivery(t *testing.T) {
	broker := proxyTestBroker(t)
	h := &Handler{Secrets: broker, CaptureLimit: 1024}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": {"application/json"}, "X-Secret": {"real-api-key"}},
		Body:       io.NopCloser(strings.NewReader(`{"token":"real-api-key"}`)),
	}
	item := &flow.Flow{}
	if err := h.mediateResponse(resp, "agent", "allowed.example", item); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"token":"`+testPlaceholder+`"}` || resp.Header.Get("X-Secret") != testPlaceholder {
		t.Fatalf("response body = %q header = %q", body, resp.Header.Get("X-Secret"))
	}
	if item.Capture.ResponseBody == nil || item.Capture.ResponseBody.Text != `{"token":"[secret:api_key]"}` {
		t.Fatalf("capture = %#v", item.Capture)
	}
}

func TestResponseCaptureInfersEventStreamWithoutContentType(t *testing.T) {
	body := "data: {\"message\":\"first line\\nsecond line\"}\n\ndata: [DONE]\n\n"
	resp := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
	item := &flow.Flow{}
	if err := (&Handler{CaptureLimit: 4096, MediationLimit: 4096}).mediateResponse(resp, "agent", "allowed.example", item); err != nil {
		t.Fatal(err)
	}
	if item.Capture.ResponseBody == nil || item.Capture.ResponseBody.Omitted || item.Capture.ResponseBody.ContentType != "text/event-stream" || item.Capture.ResponseBody.Text != body {
		t.Fatalf("response capture = %#v", item.Capture.ResponseBody)
	}
}

func TestResponseCaptureInfersJSONWithoutContentType(t *testing.T) {
	body := `{"message":"hello"}`
	resp := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
	item := &flow.Flow{}
	if err := (&Handler{CaptureLimit: 4096, MediationLimit: 4096}).mediateResponse(resp, "agent", "allowed.example", item); err != nil {
		t.Fatal(err)
	}
	if item.Capture.ResponseBody == nil || item.Capture.ResponseBody.Omitted || item.Capture.ResponseBody.ContentType != "application/json" || item.Capture.ResponseBody.Text != body {
		t.Fatalf("response capture = %#v", item.Capture.ResponseBody)
	}
}

func TestResponseCaptureRedactsReflectedCredentialHeaderValue(t *testing.T) {
	credential := "Bearer TEST_VISIBLE_CREDENTIAL"
	request := &http.Request{Header: http.Header{"Authorization": {credential}}}
	resp := &http.Response{
		StatusCode: http.StatusUnauthorized,
		Status:     "401 Unauthorized",
		Header:     http.Header{"Content-Type": {"text/plain"}},
		Body:       io.NopCloser(strings.NewReader("rejected " + credential)),
		Request:    request,
	}
	item := &flow.Flow{}
	if err := (&Handler{CaptureLimit: 1024}).mediateResponse(resp, "agent", "allowed.example", item); err != nil {
		t.Fatal(err)
	}
	if item.Capture.ResponseBody == nil || item.Capture.ResponseBody.Text != "rejected [redacted]" {
		t.Fatalf("response capture = %#v", item.Capture.ResponseBody)
	}
}

func TestRequestAndResponseTrailersAreMediated(t *testing.T) {
	broker := proxyTestBroker(t)
	req := &http.Request{
		Method: http.MethodPost, Host: "allowed.example",
		Header:  http.Header{"Content-Type": {"application/json"}, "Expect": {"100-continue"}},
		Body:    io.NopCloser(strings.NewReader(`{"ok":true}`)),
		Trailer: http.Header{"X-Trailer-Token": {testPlaceholder}},
	}
	requestFlow := &flow.Flow{}
	h := &Handler{Secrets: broker, CaptureLimit: 1024, MediationLimit: 4096}
	if err := h.mediateRequest(req, "agent", "allowed.example", true, requestFlow); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Expect") != "" || req.Trailer.Get("X-Trailer-Token") != "real-api-key" || req.ContentLength != -1 {
		t.Fatalf("request headers = %#v trailer = %#v length = %d", req.Header, req.Trailer, req.ContentLength)
	}
	resp := &http.Response{
		StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Content-Type": {"text/plain"}},
		Body: io.NopCloser(strings.NewReader("ok")), Trailer: http.Header{"X-Trailer-Token": {"real-api-key"}},
	}
	responseFlow := &flow.Flow{}
	if err := h.mediateResponse(resp, "agent", "allowed.example", responseFlow); err != nil {
		t.Fatal(err)
	}
	if resp.Trailer.Get("X-Trailer-Token") != testPlaceholder || resp.ContentLength != -1 || len(responseFlow.ResponseSecretNames) != 1 {
		t.Fatalf("response trailer = %#v length = %d flow = %#v", resp.Trailer, resp.ContentLength, responseFlow)
	}
}

func TestMediateResponseTruncatesCaptureWithoutRejectingTraffic(t *testing.T) {
	h := &Handler{CaptureLimit: 4, MediationLimit: 16}
	resp := &http.Response{Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("12345"))}
	item := &flow.Flow{}
	if err := h.mediateResponse(resp, "agent", "allowed.example", item); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "12345" || !item.Capture.Truncated || item.Capture.ResponseBody == nil || item.Capture.ResponseBody.Text != "1234" {
		t.Fatalf("body = %q capture = %#v", body, item.Capture)
	}
}

func TestMediateResponseFailsClosedAboveMediationLimit(t *testing.T) {
	h := &Handler{CaptureLimit: 4, MediationLimit: 4}
	resp := &http.Response{Header: make(http.Header), Body: io.NopCloser(strings.NewReader("12345"))}
	if err := h.mediateResponse(resp, "agent", "allowed.example", &flow.Flow{}); err == nil {
		t.Fatal("mediateResponse succeeded")
	}
}
