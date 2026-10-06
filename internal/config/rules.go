package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/abagile/veilgate/internal/hostpattern"
)

// Rule narrows what a client may send to hosts matching Host. A host that has
// at least one rule is restricted: a request must satisfy some rule for that
// host (all of a rule's non-empty fields must match), otherwise it is denied.
// Hosts without any rule are not restricted by rules.
//
// Rules are enforced on intercepted requests, so a host with rules is never
// handled as an opaque tunnel.
//
// A rule names its hosts with Host or Hosts (not both). Validate expands Hosts
// into one single-host rule each, so Hosts is empty after validation.
type Rule struct {
	// Host is an exact host or leftmost-label wildcard pattern.
	Host string `json:"host,omitempty"`
	// Hosts applies the rule to every listed host pattern.
	Hosts []string `json:"hosts,omitempty"`
	// Methods lists permitted HTTP methods. Empty means any method.
	Methods []string `json:"methods,omitempty"`
	// PathPrefixes lists permitted URL path prefixes. A prefix ending in "/"
	// matches that subtree; any other prefix matches the exact path or the
	// subtree below it. Empty means any path.
	PathPrefixes []string `json:"path_prefixes,omitempty"`
	// MaxRequestBytes caps the request body size. Zero means no cap.
	MaxRequestBytes int64 `json:"max_request_bytes,omitempty"`
}

// normalize validates and canonicalizes every field except the host names.
func (r *Rule) normalize() error {
	if len(r.Methods) == 0 && len(r.PathPrefixes) == 0 && r.MaxRequestBytes == 0 {
		return errors.New("rule must set methods, path_prefixes, or max_request_bytes")
	}
	for i, method := range r.Methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if !validMethod(method) {
			return fmt.Errorf("methods[%d]: invalid HTTP method %q", i, method)
		}
		r.Methods[i] = method
	}
	for i, prefix := range r.PathPrefixes {
		if err := validPathPrefix(prefix); err != nil {
			return fmt.Errorf("path_prefixes[%d]: %w", i, err)
		}
	}
	if r.MaxRequestBytes < 0 {
		return errors.New("max_request_bytes must not be negative")
	}
	return nil
}

// expandRules normalizes rules and replaces each multi-host rule with one
// single-host rule per distinct host, preserving order.
func expandRules(rules []Rule) ([]Rule, error) {
	var expanded []Rule
	for i := range rules {
		rule := rules[i]
		if rule.Host != "" && len(rule.Hosts) > 0 {
			return nil, fmt.Errorf("allowed_rules[%d]: set host or hosts, not both", i)
		}
		patterns := rule.Hosts
		if rule.Host != "" {
			patterns = []string{rule.Host}
		}
		if len(patterns) == 0 {
			return nil, fmt.Errorf("allowed_rules[%d]: host or hosts is required", i)
		}
		if err := rule.normalize(); err != nil {
			return nil, fmt.Errorf("allowed_rules[%d]: %w", i, err)
		}
		var seen []string
		for j, pattern := range patterns {
			host, err := normalizePattern(pattern)
			if err != nil {
				return nil, fmt.Errorf("allowed_rules[%d] hosts[%d]: %w", i, j, err)
			}
			if slices.Contains(seen, host) {
				continue
			}
			seen = append(seen, host)
			single := rule
			single.Host, single.Hosts = host, nil
			single.Methods = slices.Clone(rule.Methods)
			single.PathPrefixes = slices.Clone(rule.PathPrefixes)
			expanded = append(expanded, single)
		}
	}
	return expanded, nil
}

func validMethod(method string) bool {
	if method == "" || method == "CONNECT" {
		return false
	}
	for _, character := range method {
		if character < 'A' || character > 'Z' {
			return false
		}
	}
	return true
}

// validPathPrefix requires a canonical absolute path so a prefix cannot be
// satisfied by, or hide, dot segments or encoded separators.
func validPathPrefix(prefix string) error {
	if !strings.HasPrefix(prefix, "/") {
		return fmt.Errorf("%q must start with /", prefix)
	}
	if strings.ContainsAny(prefix, "%?#\\") {
		return fmt.Errorf("%q must not contain %%, ?, #, or \\", prefix)
	}
	for _, character := range prefix {
		if character <= 0x20 || character == 0x7f {
			return fmt.Errorf("%q must not contain whitespace or control characters", prefix)
		}
	}
	segments := strings.Split(strings.TrimSuffix(prefix[1:], "/"), "/")
	if prefix != "/" && slices.Contains(segments, "") {
		return fmt.Errorf("%q must not contain empty path segments", prefix)
	}
	if slices.Contains(segments, ".") || slices.Contains(segments, "..") {
		return fmt.Errorf("%q must not contain . or .. segments", prefix)
	}
	return nil
}

func (r *Rule) matches(method, path string) bool {
	if len(r.Methods) > 0 && !slices.Contains(r.Methods, method) {
		return false
	}
	if len(r.PathPrefixes) == 0 {
		return true
	}
	return slices.ContainsFunc(r.PathPrefixes, func(prefix string) bool {
		if strings.HasSuffix(prefix, "/") {
			return strings.HasPrefix(path, prefix)
		}
		return path == prefix || strings.HasPrefix(path, prefix+"/")
	})
}

// HasRulesFor reports whether any allowed_rules entry applies to host.
func (c *Client) HasRulesFor(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return slices.ContainsFunc(c.AllowedRules, func(rule Rule) bool {
		return hostpattern.Matches([]string{rule.Host}, host)
	})
}

// MatchRule evaluates a request against allowed_rules. When no rule applies to
// host it returns (nil, true). Otherwise it returns the first rule that
// permits method and the decoded, validated path, or (nil, false).
func (c *Client) MatchRule(host, method, path string) (*Rule, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	restricted := false
	for i := range c.AllowedRules {
		rule := &c.AllowedRules[i]
		if !hostpattern.Matches([]string{rule.Host}, host) {
			continue
		}
		restricted = true
		if rule.matches(method, path) {
			return rule, true
		}
	}
	return nil, !restricted
}

// InspectsHost reports whether host matches InspectHosts. Like the other
// handling lists, it does not grant destination access.
func (c *Client) InspectsHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return validHostname(host) && hostpattern.Matches(c.InspectHosts, host)
}
