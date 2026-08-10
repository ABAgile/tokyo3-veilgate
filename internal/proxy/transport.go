package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

const (
	maxCachedUpstreamTransports = 64
	upstreamIdleConnTimeout     = 5 * time.Minute
)

type upstreamTransportKey struct {
	scheme string
	host   string
	ip     netip.Addr
	port   int
}

type cachedUpstreamTransport struct {
	transport *http.Transport
	lastUsed  time.Time
}

// upstreamTransport returns a concurrency-safe persistent transport pinned to
// one validated host/IP/port tuple. Re-resolving each request still controls
// which pool may be used, while matching results reuse HTTP/1.1 connections or
// multiplex over a long-lived HTTP/2 connection.
func (h *Handler) upstreamTransport(scheme, host string, ip netip.Addr, port int) *http.Transport {
	key := upstreamTransportKey{
		scheme: strings.ToLower(scheme),
		host:   strings.ToLower(strings.TrimSuffix(host, ".")),
		ip:     ip.Unmap(),
		port:   port,
	}
	now := time.Now()
	h.transportMu.Lock()
	defer h.transportMu.Unlock()
	if cached := h.transports[key]; cached != nil {
		cached.lastUsed = now
		return cached.transport
	}
	if h.transports == nil {
		h.transports = make(map[upstreamTransportKey]*cachedUpstreamTransport)
	}
	if len(h.transports) >= maxCachedUpstreamTransports {
		h.evictOldestTransportLocked()
	}
	transport := h.newUpstreamTransport(key)
	h.transports[key] = &cachedUpstreamTransport{transport: transport, lastUsed: now}
	return transport
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
	if oldest != nil {
		delete(h.transports, oldestKey)
		oldest.transport.CloseIdleConnections()
	}
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
	transports := make([]*http.Transport, 0, len(h.transports))
	for _, cached := range h.transports {
		transports = append(transports, cached.transport)
	}
	h.transports = nil
	h.transportMu.Unlock()
	for _, transport := range transports {
		transport.CloseIdleConnections()
	}
	return closeErr
}
