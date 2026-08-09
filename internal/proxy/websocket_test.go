package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/abagile/veilgate/internal/flow"
)

func TestRelayWebSocketReassemblesFragmentedText(t *testing.T) {
	var wire bytes.Buffer
	writer := &wsEndpoint{writer: &wire, writeMask: true}
	if err := writer.write(wsFrame{fin: false, opcode: wsText, payload: []byte(`{"message":`)}); err != nil {
		t.Fatal(err)
	}
	if err := writer.write(wsFrame{fin: true, opcode: wsContinuation, payload: []byte(`"hello"}`)}); err != nil {
		t.Fatal(err)
	}
	if err := writer.write(wsFrame{fin: true, opcode: wsClose, payload: wsClosePayload(1000, "done")}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	item := &flow.Flow{}
	h := &Handler{CaptureLimit: 1024}
	_, err := h.relayWebSocket(context.Background(), "client-to-upstream",
		&wsEndpoint{reader: bufio.NewReader(&wire), expectMask: true},
		&wsEndpoint{writer: &output, writeMask: true},
		&wsCapture{item: item, remaining: 1024}, "agent", "api.example.com")
	if !errors.Is(err, errWebSocketClosed) {
		t.Fatalf("relay error = %v", err)
	}
	frame, err := readWebSocketFrame(bufio.NewReader(&output), true, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !frame.fin || frame.opcode != wsText || string(frame.payload) != `{"message":"hello"}` || len(item.Capture.WebSocketMessages) != 1 {
		t.Fatalf("frame = %#v capture = %#v", frame, item.Capture)
	}
}

func TestRelayWebSocketForwardsBinaryAndCapturesMetadata(t *testing.T) {
	var wire bytes.Buffer
	writer := &wsEndpoint{writer: &wire, writeMask: true}
	payload := []byte{1, 2, 3}
	if err := writer.write(wsFrame{fin: true, opcode: wsBinary, payload: payload}); err != nil {
		t.Fatal(err)
	}
	if err := writer.write(wsFrame{fin: true, opcode: wsClose, payload: wsClosePayload(1000, "done")}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	item := &flow.Flow{}
	h := &Handler{CaptureLimit: 1024, MediationLimit: 4096}
	_, err := h.relayWebSocket(context.Background(), "client-to-upstream",
		&wsEndpoint{reader: bufio.NewReader(&wire), expectMask: true},
		&wsEndpoint{writer: &output, writeMask: true},
		&wsCapture{item: item, remaining: 1024}, "agent", "api.example.com")
	if !errors.Is(err, errWebSocketClosed) {
		t.Fatalf("relay error = %v", err)
	}
	frame, err := readWebSocketFrame(bufio.NewReader(&output), true, 4096)
	if err != nil || frame.opcode != wsBinary || !bytes.Equal(frame.payload, payload) {
		t.Fatalf("binary frame = %#v err = %v", frame, err)
	}
	if len(item.Capture.WebSocketMessages) != 1 || item.Capture.WebSocketMessages[0].Kind != "binary" || item.Capture.WebSocketMessages[0].Size != 3 || item.Capture.WebSocketMessages[0].SHA256 == "" || item.Capture.WebSocketMessages[0].Text != "" {
		t.Fatalf("capture = %#v", item.Capture)
	}
}

func TestRelayWebSocketRejectsBinaryPlaceholder(t *testing.T) {
	var wire bytes.Buffer
	writer := &wsEndpoint{writer: &wire, writeMask: true}
	if err := writer.write(wsFrame{fin: true, opcode: wsBinary, payload: []byte(testPlaceholder)}); err != nil {
		t.Fatal(err)
	}
	h := &Handler{Secrets: proxyTestBroker(t), CaptureLimit: 1024, MediationLimit: 4096}
	_, err := h.relayWebSocket(context.Background(), "client-to-upstream",
		&wsEndpoint{reader: bufio.NewReader(&wire), expectMask: true},
		&wsEndpoint{writer: &bytes.Buffer{}, writeMask: true},
		&wsCapture{item: &flow.Flow{}, remaining: 1024}, "agent", "allowed.example")
	if err == nil || !strings.Contains(err.Error(), "binary") {
		t.Fatalf("relay error = %v", err)
	}
}

func TestRelayWebSocketAttributesRejectedFrames(t *testing.T) {
	for _, tc := range []struct {
		name   string
		frame  wsFrame
		reason string
	}{
		{name: "binary", frame: wsFrame{fin: true, opcode: wsBinary, payload: []byte("prefix " + testPlaceholder)}, reason: "binary WebSocket messages"},
		{name: "control", frame: wsFrame{fin: true, opcode: wsPing, payload: []byte(testPlaceholder)}, reason: "WebSocket control frames"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var wire bytes.Buffer
			writer := &wsEndpoint{writer: &wire, writeMask: true}
			if err := writer.write(tc.frame); err != nil {
				t.Fatal(err)
			}
			item := &flow.Flow{}
			h := &Handler{Secrets: proxyTestBroker(t), CaptureLimit: 1024, MediationLimit: 4096}
			_, err := h.relayWebSocket(context.Background(), "client-to-upstream",
				&wsEndpoint{reader: bufio.NewReader(&wire), expectMask: true},
				&wsEndpoint{writer: &bytes.Buffer{}, writeMask: true},
				&wsCapture{item: item, remaining: 1024}, "agent", "allowed.example")
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("relay error = %v", err)
			}
			// The dropped connection must be attributable to a named secret.
			if !strings.Contains(err.Error(), "api_key") {
				t.Fatalf("error omits secret name: %v", err)
			}
			if strings.Contains(err.Error(), testPlaceholder) || strings.Contains(err.Error(), "real-api-key") {
				t.Fatalf("error leaks secret material: %v", err)
			}
			if len(item.SecretNames) != 1 || item.SecretNames[0] != "api_key" {
				t.Fatalf("flow secret names = %#v", item.SecretNames)
			}
		})
	}
}

func TestRelayWebSocketRejectsInboundBinarySecret(t *testing.T) {
	var wire bytes.Buffer
	writer := &wsEndpoint{writer: &wire}
	if err := writer.write(wsFrame{fin: true, opcode: wsBinary, payload: []byte("prefix real-api-key suffix")}); err != nil {
		t.Fatal(err)
	}
	h := &Handler{Secrets: proxyTestBroker(t), CaptureLimit: 1024, MediationLimit: 4096}
	_, err := h.relayWebSocket(context.Background(), "upstream-to-client",
		&wsEndpoint{reader: bufio.NewReader(&wire)},
		&wsEndpoint{writer: &bytes.Buffer{}},
		&wsCapture{item: &flow.Flow{}, remaining: 1024}, "agent", "allowed.example")
	if err == nil || !strings.Contains(err.Error(), "secret material") {
		t.Fatalf("relay error = %v", err)
	}
}

func TestWebSocketNoContextCompressionRoundTrip(t *testing.T) {
	original := []byte(`{"message":"hello hello hello"}`)
	compressed, err := compressWebSocketMessage(original)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decompressWebSocketMessage(compressed, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, original) {
		t.Fatalf("decoded = %q", decoded)
	}
	if !validNoContextDeflate("permessage-deflate; server_no_context_takeover; client_no_context_takeover") {
		t.Fatal("valid no-context negotiation rejected")
	}
}

func TestReadWebSocketFrameRejectsReservedBitsAndOversize(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"reserved bit", []byte{0xa1, 0x00}},
		{"oversize", []byte{0x81, 0x7e, 0x04, 0x01}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := readWebSocketFrame(bufio.NewReader(bytes.NewReader(tc.wire)), false, 1024); err == nil {
				t.Fatal("readWebSocketFrame succeeded")
			}
		})
	}
}
