// Package config loads and validates veilgated's client policy.
package config

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/abagile/veilgate/internal/hostpattern"
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
	OpaqueHosts           []string `json:"opaque_hosts,omitempty"`
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
	// Tokens are compared by digest so the check never keys a map on raw
	// credential material.
	tokens := make(map[[sha256.Size]byte]string, len(f.Clients))
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
		// A shared token makes identity ambiguous: authentication could only
		// resolve it by guessing, and every audit record for one client would
		// be attributable to the other.
		digest := sha256.Sum256([]byte(c.Token))
		if owner, exists := tokens[digest]; exists {
			return fmt.Errorf("clients %q and %q share the same token", owner, c.Name)
		}
		tokens[digest] = c.Name
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
		for j, pattern := range c.OpaqueHosts {
			normalized, err := normalizePattern(pattern)
			if err != nil {
				return fmt.Errorf("client %q opaque_hosts[%d]: %w", c.Name, j, err)
			}
			c.OpaqueHosts[j] = normalized
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
	return hostpattern.Normalize(pattern)
}

func validHostname(host string) bool {
	return hostpattern.Valid(host)
}

// Authenticate returns the client matching a bearer token. Every configured
// token is compared to avoid making the first matching position observable.
//
// An ambiguous credential is refused rather than resolved. Validate rejects
// duplicate tokens, so more than one match means the policy reached this point
// unvalidated; picking a winner there would silently grant whichever identity
// happened to be listed last.
func (f *File) Authenticate(token string) (*Client, bool) {
	var match *Client
	matches := 0
	for i := range f.Clients {
		candidate := &f.Clients[i]
		if len(token) == len(candidate.Token) && subtle.ConstantTimeCompare([]byte(token), []byte(candidate.Token)) == 1 {
			match = candidate
			matches++
		}
	}
	if matches != 1 {
		return nil, false
	}
	return match, true
}

// HasObservationClients reports whether any identity permits all public hosts.
// The mode is usable with or without TLS interception; callers may use this
// to describe policy scope without implying application-data visibility.
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
	return hostpattern.Matches(c.AllowedHosts, host)
}

// UsesOpaqueTunnel reports whether an allowed destination should remain an
// opaque TCP tunnel instead of being TLS-intercepted. OpaqueHosts does not
// grant destination access; Allows must still succeed separately.
func (c *Client) UsesOpaqueTunnel(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return validHostname(host) && hostpattern.Matches(c.OpaqueHosts, host)
}
