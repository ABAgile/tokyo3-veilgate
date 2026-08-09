// Package config loads and validates veilgated's client policy.
package config

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
)

// File is the on-disk client policy document.
type File struct {
	Clients []Client `json:"clients"`
}

// Client binds one proxy credential to an identity and destination policy.
type Client struct {
	Name                  string   `json:"name"`
	Token                 string   `json:"token"`
	AllowedHosts          []string `json:"allowed_hosts,omitempty"`
	AllowedPorts          []int    `json:"allowed_ports,omitempty"`
	ObserveAllPublicHosts bool     `json:"observe_all_public_hosts,omitempty"`
}

// Load reads and validates a client policy file.
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client policy: %w", err)
	}
	var f File
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("decode client policy: %w", err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode client policy: trailing JSON data")
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// Validate checks identities, credentials, host patterns, and ports.
func (f *File) Validate() error {
	if len(f.Clients) == 0 {
		return errors.New("client policy must contain at least one client")
	}
	names := make(map[string]struct{}, len(f.Clients))
	for i := range f.Clients {
		c := &f.Clients[i]
		c.Name = strings.TrimSpace(c.Name)
		if c.Name == "" {
			return fmt.Errorf("clients[%d].name is required", i)
		}
		if _, exists := names[c.Name]; exists {
			return fmt.Errorf("duplicate client name %q", c.Name)
		}
		names[c.Name] = struct{}{}
		if len(c.Token) < 24 {
			return fmt.Errorf("client %q token must be at least 24 characters", c.Name)
		}
		if len(c.AllowedHosts) == 0 && !c.ObserveAllPublicHosts {
			return fmt.Errorf("client %q must allow at least one host or enable observe_all_public_hosts", c.Name)
		}
		for j, pattern := range c.AllowedHosts {
			normalized, err := normalizePattern(pattern)
			if err != nil {
				return fmt.Errorf("client %q allowed_hosts[%d]: %w", c.Name, j, err)
			}
			c.AllowedHosts[j] = normalized
		}
		if len(c.AllowedPorts) == 0 {
			c.AllowedPorts = []int{443}
		}
		for _, port := range c.AllowedPorts {
			if port < 1 || port > 65535 {
				return fmt.Errorf("client %q has invalid port %d", c.Name, port)
			}
		}
	}
	return nil
}

func normalizePattern(pattern string) (string, error) {
	pattern = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(pattern, ".")))
	host := strings.TrimPrefix(pattern, "*.")
	if host == "" || strings.Contains(host, "*") || !validHostname(host) {
		return "", fmt.Errorf("invalid host pattern %q", pattern)
	}
	if strings.HasPrefix(pattern, "*.") {
		return "*." + host, nil
	}
	return host, nil
}

func validHostname(host string) bool {
	if len(host) > 253 || strings.ContainsAny(host, ":/@") {
		return false
	}
	for _, r := range host {
		if r > 127 {
			return false
		}
	}
	for label := range strings.SplitSeq(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

// Authenticate returns the client matching a bearer token. Every configured
// token is compared to avoid making the first matching position observable.
func (f *File) Authenticate(token string) (*Client, bool) {
	var match *Client
	for i := range f.Clients {
		candidate := &f.Clients[i]
		if len(token) == len(candidate.Token) && subtle.ConstantTimeCompare([]byte(token), []byte(candidate.Token)) == 1 {
			match = candidate
		}
	}
	return match, match != nil
}

// HasObservationClients reports whether any identity permits all public hosts.
func (f *File) HasObservationClients() bool {
	for _, client := range f.Clients {
		if client.ObserveAllPublicHosts {
			return true
		}
	}
	return false
}

// Allows reports whether client may connect to host:port. Observation clients
// accept any syntactically valid hostname here; the proxy's resolver still
// requires every selected destination address to be public.
func (c *Client) Allows(host string, port int) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if !validHostname(host) || net.ParseIP(host) != nil || !slices.Contains(c.AllowedPorts, port) {
		return false
	}
	if c.ObserveAllPublicHosts {
		return true
	}
	for _, pattern := range c.AllowedHosts {
		if pattern == host {
			return true
		}
		if suffix, ok := strings.CutPrefix(pattern, "*."); ok && strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}
