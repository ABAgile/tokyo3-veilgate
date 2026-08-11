// Package hostpattern validates and matches configured hostname patterns.
package hostpattern

import (
	"fmt"
	"strings"
)

// Normalize validates an exact or leftmost-label wildcard hostname pattern.
func Normalize(pattern string) (string, error) {
	pattern = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
	wildcard := strings.HasPrefix(pattern, "*.")
	host := strings.TrimPrefix(pattern, "*.")
	if host == "" || !Valid(host) {
		return "", fmt.Errorf("invalid host pattern %q", pattern)
	}
	if wildcard {
		return "*." + host, nil
	}
	return host, nil
}

// Valid reports whether host is a syntactically valid ASCII hostname.
func Valid(host string) bool {
	if len(host) > 253 || strings.ContainsAny(host, ":/@") {
		return false
	}
	for _, character := range host {
		if character > 127 {
			return false
		}
	}
	for label := range strings.SplitSeq(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

// Matches reports whether host matches an exact or leftmost-label wildcard
// pattern. The caller remains responsible for validating host syntax.
func Matches(patterns []string, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, pattern := range patterns {
		if pattern == host {
			return true
		}
		if suffix, ok := strings.CutPrefix(pattern, "*."); ok && strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}
