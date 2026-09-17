package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/abagile/veilgate/internal/flow"
)

func TestHTTPCompressionRoundTrip(t *testing.T) {
	original := []byte(`{"message":"hello","items":[1,2,3]}`)
	for _, encoding := range []string{"identity", "gzip", "deflate", "br", "zstd"} {
		t.Run(encoding, func(t *testing.T) {
			encoded, err := encodeHTTPBody(original, encoding, 4096)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeHTTPBody(encoded, encoding, 4096)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decoded, original) {
				t.Fatalf("decoded = %q", decoded)
			}
		})
	}
}

func TestCompressedRequestSubstitutionAndHeaderCapture(t *testing.T) {
	broker := proxyTestBroker(t)
	body, err := encodeHTTPBody([]byte(`{"token":"`+testPlaceholder+`"}`), "gzip", 4096)
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{
		Method: http.MethodPost,
		Host:   "allowed.example",
		URL:    &url.URL{Path: "/v1"},
		Header: http.Header{
			"Authorization":    {"Bearer " + testPlaceholder},
			"Content-Type":     {"application/json"},
			"Content-Encoding": {"gzip"},
			"X-Trace":          {"visible"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}
	item := &flow.Flow{}
	h := &Handler{Secrets: broker, CaptureLimit: 4096}
	if err := h.mediateRequest(req, "agent", "allowed.example", true, item); err != nil {
		t.Fatal(err)
	}
	wire, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeHTTPBody(wire, "gzip", 4096)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != `{"token":"real-api-key"}` || item.Capture.RequestBody == nil || item.Capture.RequestBody.Text != `{"token":"[secret:api_key]"}` {
		t.Fatalf("decoded = %q capture = %#v", decoded, item.Capture)
	}
	captured := headerValues(item.Capture.RequestHeaders)
	if captured["Authorization"] != "[redacted]" || captured["X-Trace"] != "visible" || captured["Content-Encoding"] != "gzip" {
		t.Fatalf("headers = %#v", captured)
	}
}

func TestCompressedResponseScrubbingAndHeaderCapture(t *testing.T) {
	broker := proxyTestBroker(t)
	encoded, err := encodeHTTPBody([]byte(`{"token":"real-api-key"}`), "br", 4096)
	if err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header: http.Header{
			"Content-Type":     {"application/json"},
			"Content-Encoding": {"br"},
			"Set-Cookie":       {"session=private"},
		},
		Body: io.NopCloser(bytes.NewReader(encoded)),
	}
	item := &flow.Flow{}
	h := &Handler{Secrets: broker, CaptureLimit: 4096}
	if err := h.mediateResponse(resp, "agent", "allowed.example", item); err != nil {
		t.Fatal(err)
	}
	wire, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeHTTPBody(wire, "br", 4096)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != `{"token":"`+testPlaceholder+`"}` || item.BytesReceivedDecoded != int64(len(`{"token":"real-api-key"}`)) || item.Capture.ResponseBody == nil || item.Capture.ResponseBody.Text != `{"token":"[secret:api_key]"}` {
		t.Fatalf("decoded = %q decoded size = %d capture = %#v", decoded, item.BytesReceivedDecoded, item.Capture)
	}
	if got := headerValues(item.Capture.ResponseHeaders)["Set-Cookie"]; got != "[redacted]" {
		t.Fatalf("captured Set-Cookie = %q", got)
	}
}

func TestHeadResponseWithContentEncodingCapturesHeadersWithoutBody(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Encoding": {"gzip"}, "Content-Length": {"100"}},
		Body:       http.NoBody,
		Request:    &http.Request{Method: http.MethodHead},
	}
	item := &flow.Flow{}
	if err := (&Handler{CaptureLimit: 1024}).mediateResponse(resp, "agent", "allowed.example", item); err != nil {
		t.Fatal(err)
	}
	if item.Capture.ResponseBody != nil || headerValues(item.Capture.ResponseHeaders)["Content-Encoding"] != "gzip" {
		t.Fatalf("capture = %#v", item.Capture)
	}
}

func TestContentEncodingRejectsStackedAndUnknownCodings(t *testing.T) {
	for _, value := range []string{"gzip, br", "compress"} {
		if _, err := contentEncoding(http.Header{"Content-Encoding": {value}}); err == nil {
			t.Fatalf("contentEncoding(%q) succeeded", value)
		}
	}
}

func TestDecodedCompressionLimitFailsClosed(t *testing.T) {
	encoded, err := encodeHTTPBody([]byte(strings.Repeat("a", 2048)), "gzip", 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeHTTPBody(encoded, "gzip", 1024); err == nil {
		t.Fatal("decodeHTTPBody succeeded")
	}
}

func headerValues(headers []flow.HeaderCapture) map[string]string {
	values := make(map[string]string, len(headers))
	for _, header := range headers {
		values[header.Name] = strings.Join(header.Values, ", ")
	}
	return values
}
