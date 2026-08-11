package proxy

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/abagile/veilgate/internal/config"
	"github.com/abagile/veilgate/internal/flow"
)

const (
	interceptedHTTP2BufferBudget = int64(256 << 20)
	maxInterceptedHTTP2Streams   = int64(64)
)

func (h *Handler) interceptedHTTP2MaxConcurrentStreams() uint32 {
	// A mediated stream can retain a decoded request and response up to the
	// mediation limit. Reserve two limits per stream and cap the total budget
	// so the HTTP/2 default of 250 cannot turn one CONNECT session into a large
	// unbounded allocation.
	streams := interceptedHTTP2BufferBudget / h.mediationLimit() / 2
	streams = max(streams, int64(1))
	streams = min(streams, maxInterceptedHTTP2Streams)
	return uint32(streams)
}

func (h *Handler) interceptHTTP2(conn *tls.Conn, outer *http.Request, identity *config.Client, host string, port int, sessionID string) (int, int64, int64, string) {
	var totalSent, totalReceived atomic.Int64
	server := &http2.Server{
		MaxConcurrentStreams:      h.interceptedHTTP2MaxConcurrentStreams(),
		MaxReadFrameSize:          1 << 20,
		MaxDecoderHeaderTableSize: 4096,
		MaxEncoderHeaderTableSize: 4096,
	}
	server.ServeConn(conn, &http2.ServeConnOpts{
		Context: outer.Context(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			started := time.Now()
			item := flow.Flow{
				SessionID:          sessionID,
				DownstreamProtocol: "h2",
				StartedAt:          started,
				Client:             identity.Name,
				Method:             req.Method,
				Scheme:             "https",
				Host:               host,
				Port:               port,
				Path:               sanitizeText(h.Secrets, sanitizedPath(req.URL)),
				Mode:               "intercepted-h2",
				Decision:           "denied",
			}
			defer func() {
				item.Duration = time.Since(started)
				h.recordFlow(item)
			}()

			if err := validateInterceptedRequest(req, host, port); err != nil {
				item.Status = http.StatusMisdirectedRequest
				item.Reason = safeReason(err)
				item.Trace("request-authority", "fail", item.Reason)
				http.Error(w, item.Reason, item.Status)
				return
			}
			item.Trace("request-authority", "pass", "HTTP/2 authority matches CONNECT authority and TLS SNI")
			if !identity.Allows(host, port) {
				item.Status = http.StatusForbidden
				item.Reason = "destination is no longer allowed by client policy"
				item.Trace("destination-acl", "fail", item.Reason)
				http.Error(w, item.Reason, item.Status)
				return
			}
			item.Trace("destination-acl", "pass", destinationPolicyDetail(identity))
			ip, err := h.resolver().Resolve(req.Context(), host)
			if err != nil {
				item.Status = http.StatusForbidden
				item.Reason = safeReason(err)
				item.Trace("destination-ip", "fail", item.Reason)
				http.Error(w, item.Reason, item.Status)
				return
			}
			item.DestinationIP = ip.String()
			item.Trace("destination-ip", "pass", ip.String())
			if err := h.mediateRequest(req, identity.Name, host, true, &item); err != nil {
				item.Status = http.StatusBadRequest
				if mediationErr, ok := errors.AsType[*mediationError](err); ok {
					item.Status = mediationErr.status
				}
				item.Reason = safeReason(err)
				item.Trace("request-mediation", "fail", item.Reason)
				http.Error(w, item.Reason, item.Status)
				return
			}
			item.Trace("secret-policy", "pass", secretTraceDetail(item.SecretNames))
			item.Trace("request-capture", "pass", "bounded sanitized capture prepared")
			item.Decision = "allowed"
			resp, sent, err := h.roundTrip(req, ip, port, "https")
			item.BytesSent = sent
			totalSent.Add(sent)
			if err != nil {
				item.Status = http.StatusBadGateway
				item.Reason = h.sanitizedReason(err)
				item.Trace("upstream", "fail", item.Reason)
				http.Error(w, "upstream request failed", item.Status)
				return
			}
			defer resp.Body.Close()
			item.UpstreamProtocol = protocolLabel(resp.ProtoMajor, resp.ProtoMinor)
			item.Trace("upstream", "pass", "response received over "+item.UpstreamProtocol)
			if streaming, _ := shouldStreamResponse(req.Method, resp.StatusCode, resp.Header.Get("Content-Type")); streaming {
				encoding, sse, err := h.prepareStreamingResponse(resp, identity.Name, host, &item)
				if err != nil {
					item.Status = http.StatusBadGateway
					item.Reason = safeReason(err)
					item.Trace("response-streaming", "fail", item.Reason)
					http.Error(w, item.Reason, item.Status)
					return
				}
				removeHopHeaders(resp.Header)
				copyHeaders(w.Header(), resp.Header)
				for name := range resp.Trailer {
					w.Header().Add("Trailer", name)
				}
				item.Status = resp.StatusCode
				w.WriteHeader(resp.StatusCode)
				received, streamErr := h.streamResponseBody(resp, w, http.NewResponseController(w).Flush, encoding, sse, identity.Name, host, &item)
				item.BytesReceived = received
				totalReceived.Add(received)
				item.ResponseSecretNames = mergeNames(item.ResponseSecretNames, h.scrubResponseMetadata(resp, identity.Name, host))
				for name, values := range resp.Trailer {
					w.Header()[name] = append([]string(nil), values...)
				}
				if streamErr != nil {
					item.Reason = safeReason(streamErr)
					item.Trace("response-streaming", "fail", item.Reason)
					return
				}
				item.Trace("response-streaming", "pass", "records scrubbed and flushed incrementally")
				return
			}
			if err := h.mediateResponse(resp, identity.Name, host, &item); err != nil {
				item.Status = http.StatusBadGateway
				item.Reason = safeReason(err)
				item.Trace("response-scrubbing", "fail", item.Reason)
				http.Error(w, item.Reason, item.Status)
				return
			}
			item.Trace("response-scrubbing", "pass", secretTraceDetail(item.ResponseSecretNames))
			removeHopHeaders(resp.Header)
			copyHeaders(w.Header(), resp.Header)
			for name := range resp.Trailer {
				w.Header().Add("Trailer", name)
			}
			item.Status = resp.StatusCode
			w.WriteHeader(resp.StatusCode)
			received, err := io.Copy(w, resp.Body)
			item.BytesReceived = received
			totalReceived.Add(received)
			for name, values := range resp.Trailer {
				w.Header()[name] = append([]string(nil), values...)
			}
			if err != nil {
				item.Reason = safeReason(err)
			}
		}),
	})
	return http.StatusOK, totalSent.Load(), totalReceived.Load(), ""
}
