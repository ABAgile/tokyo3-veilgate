package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	maxCachedUpstreamTransports = 64
	upstreamIdleConnTimeout     = 5 * time.Minute
)

var errHandlerClosed = errors.New("proxy handler is closed")

type upstreamTransportKey struct {
	scheme string
	host   string
	ip     netip.Addr
	port   int
}

type cachedUpstreamTransport struct {
	transport *http.Transport
	lastUsed  time.Time
	active    int
	draining  bool
}

// upstreamTransport returns a concurrency-safe persistent transport pinned to
// one validated host/IP/port tuple. Re-resolving each request still controls
// which pool may be used, while matching results reuse HTTP/1.1 connections or
// multiplex over a long-lived HTTP/2 connection.
func (h *Handler) upstreamTransport(scheme, host string, ip netip.Addr, port int) *http.Transport {
	h.transportMu.Lock()
	defer h.transportMu.Unlock()
	cached := h.upstreamTransportLocked(upstreamTransportKeyFor(scheme, host, ip, port))
	if cached == nil {
		return nil
	}
	return cached.transport
}

func (h *Handler) acquireUpstreamTransport(scheme, host string, ip netip.Addr, port int) *cachedUpstreamTransport {
	h.transportMu.Lock()
	defer h.transportMu.Unlock()
	cached := h.upstreamTransportLocked(upstreamTransportKeyFor(scheme, host, ip, port))
	if cached == nil {
		return nil
	}
	cached.active++
	return cached
}

func upstreamTransportKeyFor(scheme, host string, ip netip.Addr, port int) upstreamTransportKey {
	return upstreamTransportKey{
		scheme: strings.ToLower(scheme),
		host:   strings.ToLower(strings.TrimSuffix(host, ".")),
		ip:     ip.Unmap(),
		port:   port,
	}
}

func (h *Handler) upstreamTransportLocked(key upstreamTransportKey) *cachedUpstreamTransport {
	if h.transportClosed {
		return nil
	}
	now := time.Now()
	if cached := h.transports[key]; cached != nil {
		cached.lastUsed = now
		return cached
	}
	if h.transports == nil {
		h.transports = make(map[upstreamTransportKey]*cachedUpstreamTransport)
	}
	if len(h.transports) >= maxCachedUpstreamTransports {
		h.evictOldestTransportLocked()
	}
	cached := &cachedUpstreamTransport{transport: h.newUpstreamTransport(key), lastUsed: now}
	h.transports[key] = cached
	return cached
}

func (h *Handler) newUpstreamTransport(key upstreamTransportKey) *http.Transport {
	tlsTimeout := h.DialTimeout
	if tlsTimeout == 0 {
		tlsTimeout = 10 * time.Second
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DisableKeepAlives:      false,
		DisableCompression:     true,
		ForceAttemptHTTP2:      key.scheme == "https",
		MaxIdleConns:           4,
		MaxIdleConnsPerHost:    4,
		MaxConnsPerHost:        16,
		IdleConnTimeout:        upstreamIdleConnTimeout,
		TLSHandshakeTimeout:    tlsTimeout,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 1 << 20,
		ResponseHeaderTimeout:  h.upstreamResponseHeaderTimeout(),
		WriteBufferSize:        32 << 10,
		ReadBufferSize:         32 << 10,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			conn, err := h.dialContext()(ctx, network, dialAddress(key.ip, key.port))
			if err != nil {
				return nil, err
			}
			return newActivityConn(conn, h.sessionIdleTimeout()), nil
		},
	}
	if key.scheme == "https" {
		transport.TLSClientConfig = h.upstreamTLSConfig(key.host)
		transport.TLSClientConfig.NextProtos = []string{"h2", "http/1.1"}
		// Keep the minimum explicit even when a caller supplied a partial base
		// configuration.
		if transport.TLSClientConfig.MinVersion == 0 {
			transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
	}
	return transport
}

func (h *Handler) evictOldestTransportLocked() {
	var oldestKey upstreamTransportKey
	var oldest *cachedUpstreamTransport
	for key, cached := range h.transports {
		if oldest == nil || cached.lastUsed.Before(oldest.lastUsed) {
			oldestKey, oldest = key, cached
		}
	}
	if oldest == nil {
		return
	}
	delete(h.transports, oldestKey)
	oldest.draining = true
	oldest.transport.CloseIdleConnections()
	if oldest.active > 0 {
		h.drainingTransports = append(h.drainingTransports, oldest)
	}
}

func (h *Handler) releaseUpstreamTransport(cached *cachedUpstreamTransport) {
	if cached == nil {
		return
	}
	h.transportMu.Lock()
	if cached.active > 0 {
		cached.active--
	}
	closeIdle := h.transportClosed
	if cached.draining && cached.active == 0 {
		closeIdle = true
		h.removeDrainingTransportLocked(cached)
	}
	h.transportMu.Unlock()
	if closeIdle {
		cached.transport.CloseIdleConnections()
	}
}

func (h *Handler) removeDrainingTransportLocked(target *cachedUpstreamTransport) {
	for index, cached := range h.drainingTransports {
		if cached != target {
			continue
		}
		copy(h.drainingTransports[index:], h.drainingTransports[index+1:])
		h.drainingTransports[len(h.drainingTransports)-1] = nil
		h.drainingTransports = h.drainingTransports[:len(h.drainingTransports)-1]
		return
	}
}

// trackedResponseBody keeps an evicted transport alive only while a response
// is still using it. Reading to an error/EOF or closing the body releases the
// transport so its idle connections can be closed and its cache entry dropped.
type trackedResponseBody struct {
	io.ReadCloser
	release func()
	once    sync.Once
}

func (body *trackedResponseBody) Read(p []byte) (int, error) {
	n, err := body.ReadCloser.Read(p)
	if err != nil {
		body.once.Do(body.release)
	}
	return n, err
}

func (body *trackedResponseBody) Close() error {
	err := body.ReadCloser.Close()
	body.once.Do(body.release)
	return err
}

// Close finishes pending flow submissions, waits briefly for workers, and
// releases all cached idle upstream connections.
func (h *Handler) Close() error {
	h.recordMu.Lock()
	var recordCancel context.CancelFunc
	var recordQueue chan flowRecordJob
	if !h.recordClosed {
		h.recordClosed = true
		recordCancel = h.recordCancel
		recordQueue = h.recordQueue
		h.recordMu.Unlock()
		// A denied record may be waiting for queue capacity. Wait for all
		// producers before closing the channel so that send remains safe.
		h.recordSubmitWG.Wait()
		if recordQueue != nil {
			close(recordQueue)
		}
		dropped := h.recordDropped.Load()
		if dropped > 0 {
			log := h.Log
			if log == nil {
				log = slog.Default()
			}
			log.Warn("flow records dropped under backpressure", "count", dropped)
		}
	} else {
		h.recordMu.Unlock()
	}

	waited := make(chan struct{})
	go func() {
		h.recordWG.Wait()
		close(waited)
	}()
	var closeErr error
	timer := time.NewTimer(recordShutdownTimeout)
	select {
	case <-waited:
		timer.Stop()
	case <-timer.C:
		if recordCancel != nil {
			recordCancel()
		}
		closeErr = fmt.Errorf("flow recorder did not stop within %s", recordShutdownTimeout)
		log := h.Log
		if log == nil {
			log = slog.Default()
		}
		log.Error("flow recorder shutdown timed out")
	}

	h.transportMu.Lock()
	h.transportClosed = true
	transports := make([]*http.Transport, 0, len(h.transports)+len(h.drainingTransports))
	for _, cached := range h.transports {
		transports = append(transports, cached.transport)
	}
	for _, cached := range h.drainingTransports {
		transports = append(transports, cached.transport)
	}
	h.transports = nil
	h.drainingTransports = nil
	h.transportMu.Unlock()
	for _, transport := range transports {
		transport.CloseIdleConnections()
	}
	return closeErr
}
