package proxy

import (
	"bytes"
	"net/http"
	"sort"
	"strings"

	"github.com/abagile/veilgate/internal/flow"
)

func captureHeaders(header http.Header, host string, broker SecretBroker, limit int64) ([]flow.HeaderCapture, bool) {
	cloned := header.Clone()
	if host != "" {
		cloned["Host"] = []string{host}
	}
	names := make([]string, 0, len(cloned))
	for name := range cloned {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
	captures := make([]flow.HeaderCapture, 0, len(names))
	remaining := limit
	for _, name := range names {
		values := cloned[name]
		capture := flow.HeaderCapture{Name: http.CanonicalHeaderKey(name), Values: make([]string, 0, len(values))}
		for _, value := range values {
			if sensitiveHeader(name) {
				value = "[redacted]"
			} else {
				value = sanitizeText(broker, value)
			}
			cost := int64(len(capture.Name) + len(value))
			if cost > remaining {
				return append(captures, capture), true
			}
			remaining -= cost
			capture.Values = append(capture.Values, value)
		}
		captures = append(captures, capture)
	}
	return captures, false
}

func sensitiveHeader(name string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
	if strings.Contains(normalized, "authorization") || strings.Contains(normalized, "cookie") || normalized == "authentication-info" || normalized == "proxy-authentication-info" {
		return true
	}
	for _, marker := range []string{"api-key", "apikey", "token", "secret", "credential", "password", "private-key", "signature"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func sensitiveHeaderValues(header http.Header) [][]byte {
	seen := make(map[string]struct{})
	var values [][]byte
	add := func(value string) {
		value = strings.TrimSpace(value)
		if len(value) < 8 {
			return
		}
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
		values = append(values, []byte(value))
	}
	for name, entries := range header {
		if !sensitiveHeader(name) {
			continue
		}
		for _, value := range entries {
			add(value)
			if _, credential, ok := strings.Cut(value, " "); ok {
				add(credential)
			}
			if strings.Contains(strings.ToLower(name), "cookie") {
				for part := range strings.SplitSeq(value, ";") {
					if _, cookieValue, ok := strings.Cut(part, "="); ok {
						add(cookieValue)
					}
				}
			}
		}
	}
	sort.SliceStable(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	return values
}

func redactCaptureValues(data []byte, values [][]byte) []byte {
	out := append([]byte(nil), data...)
	for _, value := range values {
		out = bytes.ReplaceAll(out, value, []byte("[redacted]"))
	}
	return out
}
