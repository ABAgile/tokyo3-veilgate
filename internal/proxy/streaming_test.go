package proxy

import (
	"bufio"
	"bytes"
	"compress/flate"
	"io"
	"net/http"
	"net/http/httputil"
	"sync"
	"testing"
	"time"

	"github.com/abagile/veilgate/internal/flow"
)

type synchronizedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *synchronizedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(data)
}

func (b *synchronizedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.b.Bytes()...)
}

func TestStreamingResponseFlushesCompleteSSEEventAndScrubsSplitSecret(t *testing.T) {
	inputReader, inputWriter := io.Pipe()
	defer inputReader.Close()
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": {"text/event-stream"}},
		Body:       inputReader,
	}
	item := &flow.Flow{}
	h := &Handler{Secrets: proxyTestBroker(t), CaptureLimit: 1024, MediationLimit: 4096}
	encoding, sse, err := h.prepareStreamingResponse(resp, "agent", "allowed.example", item)
	if err != nil {
		t.Fatal(err)
	}
	var output synchronizedBuffer
	flushed := make(chan struct{}, 2)
	done := make(chan error, 1)
	go func() {
		_, streamErr := h.streamResponseBody(resp, &output, func() error {
			flushed <- struct{}{}
			return nil
		}, encoding, sse, "agent", "allowed.example", item)
		done <- streamErr
	}()
	if _, err := inputWriter.Write([]byte("data: real-")); err != nil {
		t.Fatal(err)
	}
	if _, err := inputWriter.Write([]byte("api-key\n\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-flushed:
	case <-time.After(time.Second):
		t.Fatal("first SSE event was not flushed before stream completion")
	}
	wantWire := "data: " + testPlaceholder + "\n\n"
	if got := string(output.Bytes()); got != wantWire {
		t.Fatalf("flushed output = %q", got)
	}
	if err := inputWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if item.Capture.ResponseBody == nil || item.Capture.ResponseBody.Text != "data: [secret:api_key]\n\n" {
		t.Fatalf("capture = %#v", item.Capture)
	}
}

func TestStreamingResponseSanitizesContentTypeCapture(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": {"text/event-stream; token=real-api-key"}},
		Body:       io.NopCloser(bytes.NewReader([]byte("data: safe\\n\\n"))),
	}
	item := &flow.Flow{}
	h := &Handler{Secrets: proxyTestBroker(t), CaptureLimit: 1024, MediationLimit: 4096}
	if _, _, err := h.prepareStreamingResponse(resp, "agent", "allowed.example", item); err != nil {
		t.Fatal(err)
	}
	if item.Capture.ResponseBody == nil || item.Capture.ResponseBody.ContentType != "text/event-stream; token=[secret:api_key]" {
		t.Fatalf("captured content type = %#v", item.Capture.ResponseBody)
	}
}

func TestHTTP1StreamingResponseWireFormat(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK, Status: "200 OK",
		Header: http.Header{"Content-Type": {"text/event-stream"}},
		Body:   io.NopCloser(bytes.NewReader([]byte("data: one\n\ndata: two\n\n"))),
	}
	item := &flow.Flow{}
	h := &Handler{CaptureLimit: 1024, MediationLimit: 4096}
	encoding, sse, err := h.prepareStreamingResponse(resp, "agent", "allowed.example", item)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := writeHTTP1StreamingHead(&wire, resp); err != nil {
		t.Fatal(err)
	}
	chunked := httputil.NewChunkedWriter(&wire)
	if _, err := h.streamResponseBody(resp, chunked, nil, encoding, sse, "agent", "allowed.example", item); err != nil {
		t.Fatal(err)
	}
	if err := chunked.Close(); err != nil {
		t.Fatal(err)
	}
	wire.WriteString("\r\n")
	parsed, err := http.ReadResponse(bufio.NewReader(&wire), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(parsed.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "data: one\n\ndata: two\n\n" {
		t.Fatalf("body = %q", body)
	}
}

func TestCompressedNDJSONStreamingRoundTrip(t *testing.T) {
	plain := []byte("{\"token\":\"real-api-key\"}\n{\"done\":true}\n")
	for _, encoding := range []string{"identity", "gzip", "deflate", "br", "zstd"} {
		t.Run(encoding, func(t *testing.T) {
			wire, err := encodeHTTPBody(plain, encoding, 8192)
			if err != nil {
				t.Fatal(err)
			}
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header: http.Header{
					"Content-Type":     {"application/x-ndjson"},
					"Content-Encoding": {encoding},
				},
				Body: io.NopCloser(bytes.NewReader(wire)),
			}
			item := &flow.Flow{}
			h := &Handler{Secrets: proxyTestBroker(t), CaptureLimit: 24, MediationLimit: 4096}
			selected, sse, err := h.prepareStreamingResponse(resp, "agent", "allowed.example", item)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if _, err := h.streamResponseBody(resp, &output, nil, selected, sse, "agent", "allowed.example", item); err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeHTTPBody(output.Bytes(), encoding, 8192)
			if err != nil {
				t.Fatal(err)
			}
			want := []byte("{\"token\":\"" + testPlaceholder + "\"}\n{\"done\":true}\n")
			if !bytes.Equal(decoded, want) {
				t.Fatalf("decoded = %q", decoded)
			}
			if !item.Capture.Truncated || item.Capture.ResponseBody == nil || len(item.Capture.ResponseBody.Text) > 24 {
				t.Fatalf("capture = %#v", item.Capture)
			}
		})
	}
}

func TestRawDeflateStreamingPreservesRawFraming(t *testing.T) {
	plain := []byte("{\"message\":\"raw\"}\n")
	var encoded bytes.Buffer
	writer, err := flate.NewWriter(&encoded, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/x-ndjson"}, "Content-Encoding": {"deflate"}},
		Body:       io.NopCloser(bytes.NewReader(encoded.Bytes())),
	}
	item := &flow.Flow{}
	h := &Handler{CaptureLimit: 1024, MediationLimit: 4096}
	encoding, sse, err := h.prepareStreamingResponse(resp, "agent", "allowed.example", item)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if _, err := h.streamResponseBody(resp, &output, nil, encoding, sse, "agent", "allowed.example", item); err != nil {
		t.Fatal(err)
	}

	reader := flate.NewReader(bytes.NewReader(output.Bytes()))
	decoded, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		t.Fatalf("decode forwarded raw deflate: %v", err)
	}
	if !bytes.Equal(decoded, plain) {
		t.Fatalf("decoded = %q, want %q", decoded, plain)
	}
}

func TestStreamingResponseRejectsOversizedRecord(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{"Content-Type": {"application/x-ndjson"}},
		Body:   io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), 17))),
	}
	item := &flow.Flow{}
	h := &Handler{CaptureLimit: 8, MediationLimit: 16}
	encoding, sse, err := h.prepareStreamingResponse(resp, "agent", "allowed.example", item)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.streamResponseBody(resp, io.Discard, nil, encoding, sse, "agent", "allowed.example", item); err == nil {
		t.Fatal("oversized streaming record was accepted")
	}
}
