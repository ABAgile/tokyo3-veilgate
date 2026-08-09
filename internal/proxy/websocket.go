package proxy

import (
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- SHA-1 is mandated by RFC 6455 for the handshake accept value.
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/abagile/tokyo3-base/guard"

	"github.com/abagile/veilgate/internal/flow"
)

const (
	wsContinuation = 0x0
	wsText         = 0x1
	wsBinary       = 0x2
	wsClose        = 0x8
	wsPing         = 0x9
	wsPong         = 0xa
)

var errWebSocketClosed = errors.New("WebSocket closed")

type wsFrame struct {
	fin        bool
	compressed bool
	opcode     byte
	payload    []byte
}

type wsEndpoint struct {
	reader      *bufio.Reader
	writer      io.Writer
	writeMu     sync.Mutex
	writeMask   bool
	expectMask  bool
	compression bool
}

type wsCapture struct {
	mu         sync.Mutex
	item       *flow.Flow
	broker     SecretBroker
	redactions [][]byte
	remaining  int64
}

func isWebSocketUpgrade(req *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(req.Header.Get("Upgrade")), "websocket") || headerHasToken(req.Header, "Connection", "upgrade")
}

func validateWebSocketRequest(req *http.Request) error {
	if req.Method != http.MethodGet || req.ProtoMajor != 1 || req.ProtoMinor < 1 {
		return errors.New("WebSocket upgrade requires HTTP/1.1 GET")
	}
	if !strings.EqualFold(strings.TrimSpace(req.Header.Get("Upgrade")), "websocket") || !headerHasToken(req.Header, "Connection", "upgrade") {
		return errors.New("malformed WebSocket upgrade headers")
	}
	if req.Header.Get("Sec-WebSocket-Version") != "13" {
		return errors.New("only WebSocket version 13 is supported")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.Header.Get("Sec-WebSocket-Key")))
	if err != nil || len(key) != 16 {
		return errors.New("invalid WebSocket handshake key")
	}
	return nil
}

func (h *Handler) proxyWebSocket(downstream io.Writer, downstreamReader *bufio.Reader, req *http.Request, client, host string, port int, ip netip.Addr, item *flow.Flow) (int, int64, int64, string, bool) {
	if err := validateWebSocketRequest(req); err != nil {
		reason := safeReason(err)
		item.Trace("websocket-handshake", "fail", reason)
		_ = writeSimpleResponse(downstream, req, http.StatusBadRequest, reason)
		return http.StatusBadRequest, 0, 0, reason, true
	}

	upstream, err := h.dialContext()(req.Context(), "tcp", dialAddress(ip, port))
	if err != nil {
		reason := safeReason(err)
		item.Trace("websocket-handshake", "fail", reason)
		_ = writeSimpleResponse(downstream, req, http.StatusBadGateway, "upstream connection failed")
		return http.StatusBadGateway, 0, 0, reason, true
	}
	defer upstream.Close()
	upstreamActivity := newActivityConn(upstream, h.sessionIdleTimeout())
	closers := []io.Closer{upstream}
	if closer, ok := downstream.(io.Closer); ok {
		closers = append(closers, closer)
	}
	stopContextWatcher := h.closeOnContext(req.Context(), "websocket session context", closers...)
	defer stopContextWatcher()
	tlsUpstream := tls.Client(upstreamActivity, h.upstreamTLSConfig(host))
	handshakeContext, cancel := context.WithTimeout(req.Context(), h.dialTimeout())
	defer cancel()
	if err := tlsUpstream.HandshakeContext(handshakeContext); err != nil {
		reason := safeReason(fmt.Errorf("upstream TLS handshake: %w", err))
		item.Trace("websocket-handshake", "fail", reason)
		_ = writeSimpleResponse(downstream, req, http.StatusBadGateway, "upstream TLS handshake failed")
		return http.StatusBadGateway, 0, 0, reason, true
	}
	defer tlsUpstream.Close()

	out := req.Clone(req.Context())
	out.RequestURI = ""
	out.URL.Scheme = "https"
	out.URL.Host = destinationAuthority(out.Host, port, "https")
	out.Header.Del("Proxy-Authorization")
	out.Header.Del("Proxy-Connection")
	clientCompression := offersPerMessageDeflate(req.Header)
	out.Header.Del("Sec-WebSocket-Extensions")
	if clientCompression {
		out.Header.Set("Sec-WebSocket-Extensions", "permessage-deflate; client_no_context_takeover; server_no_context_takeover")
	}
	out.Header.Set("Accept-Encoding", "identity")
	out.Close = false
	if err := out.Write(tlsUpstream); err != nil {
		reason := safeReason(err)
		item.Trace("websocket-handshake", "fail", reason)
		_ = writeSimpleResponse(downstream, req, http.StatusBadGateway, "upstream WebSocket handshake failed")
		return http.StatusBadGateway, 0, 0, reason, true
	}

	upstreamActivity.idle = h.upstreamResponseHeaderTimeout()
	upstreamActivity.prepareRead()
	upstreamReader := bufio.NewReader(tlsUpstream)
	resp, err := http.ReadResponse(upstreamReader, out)
	upstreamActivity.idle = h.sessionIdleTimeout()
	if err != nil {
		reason := safeReason(err)
		item.Trace("websocket-handshake", "fail", reason)
		_ = writeSimpleResponse(downstream, req, http.StatusBadGateway, "invalid upstream WebSocket response")
		return http.StatusBadGateway, 0, 0, reason, true
	}
	item.UpstreamProtocol = protocolLabel(resp.ProtoMajor, resp.ProtoMinor)
	if resp.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		!headerHasToken(resp.Header, "Connection", "upgrade") || resp.Header.Get("Sec-WebSocket-Accept") != webSocketAccept(req.Header.Get("Sec-WebSocket-Key")) {
		_ = resp.Body.Close()
		reason := "upstream rejected or malformed the WebSocket upgrade"
		item.Trace("websocket-handshake", "fail", reason)
		_ = writeSimpleResponse(downstream, req, http.StatusBadGateway, reason)
		return http.StatusBadGateway, 0, 0, reason, true
	}
	compression := false
	if selected := resp.Header.Get("Sec-WebSocket-Extensions"); selected != "" {
		if !clientCompression || !validNoContextDeflate(selected) {
			_ = resp.Body.Close()
			reason := "upstream selected an unsupported WebSocket extension"
			item.Trace("websocket-handshake", "fail", reason)
			_ = writeSimpleResponse(downstream, req, http.StatusBadGateway, reason)
			return http.StatusBadGateway, 0, 0, reason, true
		}
		compression = true
		resp.Header.Set("Sec-WebSocket-Extensions", "permessage-deflate; client_no_context_takeover; server_no_context_takeover")
	}
	if h.Secrets != nil {
		for name, values := range resp.Header {
			for i, value := range values {
				scrubbed, names := h.Secrets.Scrub([]byte(value), client, host)
				values[i] = string(scrubbed)
				item.ResponseSecretNames = mergeNames(item.ResponseSecretNames, names)
			}
			resp.Header[name] = values
		}
		status, names := h.Secrets.Scrub([]byte(resp.Status), client, host)
		resp.Status = string(status)
		item.ResponseSecretNames = mergeNames(item.ResponseSecretNames, names)
	}
	resp.Body = http.NoBody
	resp.ContentLength = 0
	var headersTruncated bool
	item.Capture.ResponseHeaders, headersTruncated = captureHeaders(resp.Header, "", h.Secrets, h.captureLimit())
	item.Capture.Truncated = item.Capture.Truncated || headersTruncated
	if err := resp.Write(downstream); err != nil {
		return http.StatusSwitchingProtocols, 0, 0, safeReason(err), true
	}
	mediation := "uncompressed frame mediation established"
	if compression {
		mediation = "permessage-deflate no-context-takeover mediation established"
	}
	item.Trace("websocket-handshake", "pass", mediation)

	downstreamEndpoint := &wsEndpoint{reader: downstreamReader, writer: downstream, writeMask: false, expectMask: true, compression: compression}
	upstreamEndpoint := &wsEndpoint{reader: upstreamReader, writer: tlsUpstream, writeMask: true, expectMask: false, compression: compression}
	capture := &wsCapture{item: item, broker: h.Secrets, redactions: sensitiveHeaderValues(req.Header), remaining: h.captureLimit()}
	type result struct {
		direction string
		bytes     int64
		err       error
	}
	results := make(chan result, 2)
	relay := func(direction string, src, dst *wsEndpoint) func() {
		return func() {
			bytes, err := h.relayWebSocket(req.Context(), direction, src, dst, capture, client, host)
			results <- result{direction: direction, bytes: bytes, err: err}
		}
	}
	log := h.Log
	if log == nil {
		log = slog.Default()
	}
	guard.Go(log, "websocket client relay", relay("client-to-upstream", downstreamEndpoint, upstreamEndpoint))
	guard.Go(log, "websocket upstream relay", relay("upstream-to-client", upstreamEndpoint, downstreamEndpoint))
	first := <-results
	_ = tlsUpstream.Close()
	if closer, ok := downstream.(io.Closer); ok {
		_ = closer.Close()
	}
	second := <-results
	var sent, received int64
	for _, value := range []result{first, second} {
		if value.direction == "client-to-upstream" {
			sent = value.bytes
		} else {
			received = value.bytes
		}
	}
	for _, value := range []result{first, second} {
		if value.err != nil && !errors.Is(value.err, errWebSocketClosed) && !errors.Is(value.err, net.ErrClosed) && !errors.Is(value.err, io.EOF) {
			reason := safeReason(value.err)
			item.Trace("websocket-frames", "fail", reason)
			return http.StatusSwitchingProtocols, sent, received, reason, true
		}
	}
	item.Trace("websocket-frames", "pass", "connection closed")
	return http.StatusSwitchingProtocols, sent, received, "", true
}

func (h *Handler) relayWebSocket(ctx context.Context, direction string, src, dst *wsEndpoint, capture *wsCapture, client, host string) (int64, error) {
	var total int64
	var message []byte
	var messageOpcode byte
	var messageCompressed bool
	fragmented := false
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		frame, err := readWebSocketFrame(src.reader, src.expectMask, h.mediationLimit())
		if err != nil {
			return total, err
		}
		total += int64(len(frame.payload))
		if frame.compressed && !src.compression {
			return total, errors.New("compressed WebSocket frame without negotiated extension")
		}
		switch frame.opcode {
		case wsText, wsBinary:
			if fragmented {
				return total, errors.New("new WebSocket data message before fragmented message completed")
			}
			messageOpcode = frame.opcode
			messageCompressed = frame.compressed
			message = append(message[:0], frame.payload...)
			fragmented = !frame.fin
			if fragmented {
				continue
			}
		case wsContinuation:
			if !fragmented {
				return total, errors.New("unexpected WebSocket continuation frame")
			}
			if int64(len(message)+len(frame.payload)) > h.mediationLimit() {
				return total, errCaptureLimit
			}
			message = append(message, frame.payload...)
			fragmented = !frame.fin
			if fragmented {
				continue
			}
		case wsClose, wsPing, wsPong:
			payload := frame.payload
			if direction == "client-to-upstream" && h.Secrets != nil {
				if names := h.Secrets.PlaceholderNames(payload); len(names) > 0 {
					capture.addRequestNames(names)
					return total, fmt.Errorf("secret placeholders are not allowed in WebSocket control frames: %s", strings.Join(names, ", "))
				}
			}
			if direction == "upstream-to-client" && h.Secrets != nil {
				var names []string
				payload, names = h.Secrets.Scrub(payload, client, host)
				capture.addResponseNames(names)
				if len(payload) > 125 {
					return total, errors.New("scrubbed WebSocket control frame exceeds protocol limit")
				}
			}
			if err := dst.write(wsFrame{fin: true, opcode: frame.opcode, payload: payload}); err != nil {
				return total, err
			}
			if frame.opcode == wsClose {
				return total, errWebSocketClosed
			}
			continue
		default:
			return total, errors.New("unsupported WebSocket opcode")
		}

		var uncompressed []byte
		if messageCompressed {
			uncompressed, err = decompressWebSocketMessage(message, h.mediationLimit())
			if err != nil {
				return total, err
			}
		} else {
			uncompressed = message
		}
		if messageOpcode == wsBinary {
			if direction == "client-to-upstream" && h.Secrets != nil {
				if names := h.Secrets.PlaceholderNames(uncompressed); len(names) > 0 {
					capture.addRequestNames(names)
					capture.addBinaryMessage(direction, uncompressed)
					return total, fmt.Errorf("secret placeholders are not allowed in binary WebSocket messages: %s", strings.Join(names, ", "))
				}
			}
			if direction == "upstream-to-client" && h.Secrets != nil {
				_, names := h.Secrets.Scrub(uncompressed, client, host)
				if len(names) > 0 {
					capture.addResponseNames(names)
					return total, errors.New("binary WebSocket message contains configured secret material")
				}
			}
			capture.addBinaryMessage(direction, uncompressed)
			if err := dst.write(wsFrame{fin: true, compressed: dst.compression, opcode: wsBinary, payload: uncompressed}); err != nil {
				return total, err
			}
			message = message[:0]
			continue
		}
		if !utf8.Valid(uncompressed) {
			return total, errors.New("WebSocket text message is not valid UTF-8")
		}
		transformed := uncompressed
		if direction == "client-to-upstream" {
			if h.Secrets != nil && h.Secrets.ContainsPlaceholder(transformed) {
				var names []string
				transformed, names, err = h.Secrets.SubstituteJSONMessage(transformed, client, host)
				if err != nil {
					return total, err
				}
				capture.addRequestNames(names)
			}
		} else if h.Secrets != nil {
			var names []string
			transformed, names = h.Secrets.Scrub(transformed, client, host)
			capture.addResponseNames(names)
		}
		if int64(len(transformed)) > h.mediationLimit() {
			return total, errCaptureLimit
		}
		capture.addMessage(direction, transformed)
		if err := dst.write(wsFrame{fin: true, compressed: dst.compression, opcode: wsText, payload: transformed}); err != nil {
			return total, err
		}
		message = message[:0]
	}
}

func readWebSocketFrame(reader *bufio.Reader, expectMask bool, limit int64) (wsFrame, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return wsFrame{}, err
	}
	if header[0]&0x30 != 0 {
		return wsFrame{}, errors.New("unsupported WebSocket reserved bits")
	}
	frame := wsFrame{fin: header[0]&0x80 != 0, compressed: header[0]&0x40 != 0, opcode: header[0] & 0x0f}
	if frame.compressed && (frame.opcode == wsContinuation || frame.opcode >= wsClose) {
		return wsFrame{}, errors.New("invalid compressed WebSocket frame")
	}
	masked := header[1]&0x80 != 0
	if masked != expectMask {
		return wsFrame{}, errors.New("invalid WebSocket masking direction")
	}
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		var extended [2]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return wsFrame{}, err
		}
		length = uint64(binary.BigEndian.Uint16(extended[:]))
		if length < 126 {
			return wsFrame{}, errors.New("non-canonical WebSocket frame length")
		}
	case 127:
		var extended [8]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return wsFrame{}, err
		}
		length = binary.BigEndian.Uint64(extended[:])
		if length < 65536 || length>>63 != 0 {
			return wsFrame{}, errors.New("invalid WebSocket frame length")
		}
	}
	if frame.opcode >= wsClose && (!frame.fin || length > 125) {
		return wsFrame{}, errors.New("invalid fragmented WebSocket control frame")
	}
	if length > uint64(limit) {
		return wsFrame{}, errCaptureLimit
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(reader, mask[:]); err != nil {
			return wsFrame{}, err
		}
	}
	frame.payload = make([]byte, int(length))
	if _, err := io.ReadFull(reader, frame.payload); err != nil {
		return wsFrame{}, err
	}
	if masked {
		for i := range frame.payload {
			frame.payload[i] ^= mask[i%4]
		}
	}
	if frame.opcode == wsClose {
		if len(frame.payload) == 1 || (len(frame.payload) > 2 && !utf8.Valid(frame.payload[2:])) {
			return wsFrame{}, errors.New("invalid WebSocket close payload")
		}
	}
	return frame, nil
}

func (endpoint *wsEndpoint) write(frame wsFrame) error {
	endpoint.writeMu.Lock()
	defer endpoint.writeMu.Unlock()
	var header [14]byte
	payload := frame.payload
	if frame.compressed {
		if frame.opcode == wsContinuation || frame.opcode >= wsClose {
			return errors.New("invalid compressed WebSocket frame")
		}
		var err error
		payload, err = compressWebSocketMessage(payload)
		if err != nil {
			return err
		}
	}
	header[0] = frame.opcode
	if frame.compressed {
		header[0] |= 0x40
	}
	if frame.fin {
		header[0] |= 0x80
	}
	offset := 2
	length := len(payload)
	switch {
	case length < 126:
		header[1] = byte(length)
	case length <= 65535:
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:4], uint16(length))
		offset = 4
	default:
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:10], uint64(length))
		offset = 10
	}
	if endpoint.writeMask {
		header[1] |= 0x80
		var mask [4]byte
		if _, err := rand.Read(mask[:]); err != nil {
			return fmt.Errorf("generate WebSocket mask: %w", err)
		}
		copy(header[offset:offset+4], mask[:])
		offset += 4
		payload = append([]byte(nil), payload...)
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	if _, err := endpoint.writer.Write(header[:offset]); err != nil {
		return err
	}
	_, err := endpoint.writer.Write(payload)
	return err
}

func (capture *wsCapture) addMessage(direction string, message []byte) {
	clean := sanitizeCaptureBytes(capture.broker, message, capture.redactions)
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if int64(len(clean)) > capture.remaining {
		capture.item.Capture.Truncated = true
		return
	}
	capture.remaining -= int64(len(clean))
	capture.item.Capture.WebSocketMessages = append(capture.item.Capture.WebSocketMessages, flow.WebSocketMessage{Direction: direction, Kind: "text", Text: string(clean), Size: int64(len(message))})
}

func (capture *wsCapture) addBinaryMessage(direction string, message []byte) {
	digest := sha256.Sum256(message)
	capture.mu.Lock()
	defer capture.mu.Unlock()
	const metadataCost = 128
	if capture.remaining < metadataCost {
		capture.item.Capture.Truncated = true
		return
	}
	capture.remaining -= metadataCost
	capture.item.Capture.WebSocketMessages = append(capture.item.Capture.WebSocketMessages, flow.WebSocketMessage{
		Direction: direction,
		Kind:      "binary",
		Size:      int64(len(message)),
		SHA256:    hex.EncodeToString(digest[:]),
	})
}

func (capture *wsCapture) addRequestNames(names []string) {
	capture.mu.Lock()
	capture.item.SecretNames = mergeNames(capture.item.SecretNames, names)
	capture.mu.Unlock()
}

func (capture *wsCapture) addResponseNames(names []string) {
	capture.mu.Lock()
	capture.item.ResponseSecretNames = mergeNames(capture.item.ResponseSecretNames, names)
	capture.mu.Unlock()
}

func (h *Handler) upstreamTLSConfig(host string) *tls.Config {
	config := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	if h.UpstreamTLSConfig != nil {
		config = h.UpstreamTLSConfig.Clone()
		if config.MinVersion == 0 {
			config.MinVersion = tls.VersionTLS12
		}
		config.NextProtos = []string{"http/1.1"}
	}
	config.ServerName = strings.ToLower(strings.TrimSuffix(host, "."))
	return config
}

func offersPerMessageDeflate(header http.Header) bool {
	for extension := range strings.SplitSeq(header.Get("Sec-WebSocket-Extensions"), ",") {
		name, _, _ := strings.Cut(strings.TrimSpace(extension), ";")
		if strings.EqualFold(strings.TrimSpace(name), "permessage-deflate") {
			return true
		}
	}
	return false
}

func validNoContextDeflate(value string) bool {
	parts := strings.Split(value, ";")
	if len(parts) != 3 || !strings.EqualFold(strings.TrimSpace(parts[0]), "permessage-deflate") {
		return false
	}
	parameters := map[string]bool{}
	for _, part := range parts[1:] {
		parameters[strings.ToLower(strings.TrimSpace(part))] = true
	}
	return parameters["client_no_context_takeover"] && parameters["server_no_context_takeover"]
}

func compressWebSocketMessage(message []byte) ([]byte, error) {
	var output bytes.Buffer
	writer, err := flate.NewWriter(&output, flate.DefaultCompression)
	if err != nil {
		return nil, fmt.Errorf("initialize WebSocket compression: %w", err)
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("compress WebSocket message: %w", err)
	}
	if err := writer.Flush(); err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("flush WebSocket message: %w", err)
	}
	compressed := append([]byte(nil), output.Bytes()...)
	_ = writer.Close()
	if len(compressed) < 4 || !bytes.Equal(compressed[len(compressed)-4:], []byte{0x00, 0x00, 0xff, 0xff}) {
		return nil, errors.New("invalid WebSocket compression trailer")
	}
	return compressed[:len(compressed)-4], nil
}

func decompressWebSocketMessage(message []byte, limit int64) ([]byte, error) {
	encoded := make([]byte, 0, len(message)+4)
	encoded = append(encoded, message...)
	encoded = append(encoded, 0x00, 0x00, 0xff, 0xff)
	reader := flate.NewReader(bytes.NewReader(encoded))
	defer reader.Close()
	decoded, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("decompress WebSocket message: %w", err)
	}
	if int64(len(decoded)) > limit {
		return nil, errCaptureLimit
	}
	return decoded, nil
}

func headerHasToken(header http.Header, name, token string) bool {
	for value := range strings.SplitSeq(header.Get(name), ",") {
		if strings.EqualFold(strings.TrimSpace(value), token) {
			return true
		}
	}
	return false
}

func webSocketAccept(key string) string {
	digest := sha1.Sum([]byte(strings.TrimSpace(key) + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(digest[:])
}

func wsClosePayload(code int, reason string) []byte {
	if len(reason) > 123 {
		reason = reason[:123]
	}
	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload, uint16(code))
	copy(payload[2:], reason)
	return payload
}
