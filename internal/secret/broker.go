// Package secret substitutes host-side secret values for opaque placeholders
// in authorized HTTPS request headers without exposing values to the sandbox.
package secret

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"unicode"
)

// File is the on-disk secret-broker configuration.
type File struct {
	Secrets []Definition `json:"secrets"`
}

// Definition scopes one placeholder and host environment value.
type Definition struct {
	Name         string   `json:"name"`
	ValueEnv     string   `json:"value_env"`
	Placeholder  string   `json:"placeholder"`
	Clients      []string `json:"clients"`
	AllowedHosts []string `json:"allowed_hosts"`
}

type resolved struct {
	Definition
	value                      string
	valueBytes                 []byte
	placeholderBytes           []byte
	representations            [][]byte
	placeholderRepresentations [][]byte
	marker                     []byte
}

// Broker holds resolved values only in daemon memory.
type Broker struct {
	secrets []resolved
	// trie indexes every value and placeholder representation once, so
	// matching cost does not grow with the number of configured secrets. It is
	// read-only after New returns.
	trie *needleTrie
}

// Load reads a strict JSON file and resolves each value from the host process
// environment. Missing values fail startup.
func Load(path string) (*Broker, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read secrets file: %w", err)
	}
	var file File
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("decode secrets file: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode secrets file: trailing JSON data")
	}
	return New(file, os.LookupEnv)
}

// New validates definitions and resolves values with lookup.
func New(file File, lookup func(string) (string, bool)) (*Broker, error) {
	if len(file.Secrets) == 0 {
		return nil, errors.New("secrets file must contain at least one secret")
	}
	names := make(map[string]struct{}, len(file.Secrets))
	placeholders := make(map[string]struct{}, len(file.Secrets))
	values := make(map[string]struct{}, len(file.Secrets))
	broker := &Broker{secrets: make([]resolved, 0, len(file.Secrets))}
	for i, definition := range file.Secrets {
		definition.Name = strings.TrimSpace(definition.Name)
		if !validName(definition.Name) {
			return nil, fmt.Errorf("secrets[%d].name is invalid", i)
		}
		if _, exists := names[definition.Name]; exists {
			return nil, fmt.Errorf("duplicate secret name %q", definition.Name)
		}
		names[definition.Name] = struct{}{}
		definition.ValueEnv = strings.TrimSpace(definition.ValueEnv)
		if definition.ValueEnv == "" {
			definition.ValueEnv = "VEILGATED_" + strings.ToUpper(definition.Name)
		} else if !strings.HasPrefix(definition.ValueEnv, "VEILGATED_") {
			definition.ValueEnv = "VEILGATED_" + definition.ValueEnv
		}
		definition.Placeholder = strings.TrimSpace(definition.Placeholder)
		if definition.Placeholder == "" {
			return nil, fmt.Errorf("secret %q placeholder is required", definition.Name)
		}
		definition.Placeholder = strings.TrimPrefix(definition.Placeholder, "VEILGATE_SECRET_")
		if !strings.HasPrefix(definition.Placeholder, "VEILGATED_SECRET_") {
			definition.Placeholder = "VEILGATED_SECRET_" + definition.Placeholder
		}
		if strings.ContainsAny(definition.Placeholder, "\r\n") {
			return nil, fmt.Errorf("secret %q placeholder contains a line break", definition.Name)
		}
		if _, exists := placeholders[definition.Placeholder]; exists {
			return nil, fmt.Errorf("duplicate placeholder for secret %q", definition.Name)
		}
		placeholders[definition.Placeholder] = struct{}{}
		if len(definition.Clients) == 0 || len(definition.AllowedHosts) == 0 {
			return nil, fmt.Errorf("secret %q requires clients and allowed_hosts", definition.Name)
		}
		for j, host := range definition.AllowedHosts {
			normalized, err := normalizePattern(host)
			if err != nil {
				return nil, fmt.Errorf("secret %q allowed_hosts[%d]: %w", definition.Name, j, err)
			}
			definition.AllowedHosts[j] = normalized
		}
		value, ok := lookup(definition.ValueEnv)
		if !ok || value == "" {
			return nil, fmt.Errorf("secret %q environment variable %s is unset or empty", definition.Name, definition.ValueEnv)
		}
		if len(value) < 8 || len(value) > 16*1024 || strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("secret %q value must be 8–16384 bytes without line breaks", definition.Name)
		}
		if _, exists := values[value]; exists {
			return nil, fmt.Errorf("secret %q resolves to a duplicate value", definition.Name)
		}
		if _, exists := placeholders[value]; exists {
			return nil, fmt.Errorf("secret %q value collides with a configured placeholder", definition.Name)
		}
		for existingValue := range values {
			if definition.Placeholder == existingValue {
				return nil, fmt.Errorf("secret %q placeholder collides with a configured value", definition.Name)
			}
		}
		values[value] = struct{}{}
		broker.secrets = append(broker.secrets, resolved{
			Definition:                 definition,
			value:                      value,
			valueBytes:                 []byte(value),
			placeholderBytes:           []byte(definition.Placeholder),
			representations:            secretRepresentations(value),
			placeholderRepresentations: secretRepresentations(definition.Placeholder),
			marker:                     []byte("[secret:" + definition.Name + "]"),
		})
	}
	broker.trie = newNeedleTrie(broker.secrets)
	return broker, nil
}

// Apply replaces all known placeholders found in request headers. Any use on
// plaintext HTTP, by the wrong client, or for the wrong host fails closed.
// Returned names are safe metadata; values and placeholders are never returned.
func (b *Broker) Apply(req *http.Request, client, host string, secure bool) ([]string, error) {
	if b == nil {
		return nil, nil
	}
	used := make(map[string]struct{})
	// Inspect and authorize against the original headers before staging any
	// replacement. An unauthorized placeholder must not leave a real value in
	// the request if the request is later logged, retried, or captured.
	for _, item := range b.secrets {
		found := false
		for name, values := range req.Header {
			for _, value := range values {
				_, matched, err := replaceHeaderValue(name, value, item.Placeholder, item.value)
				if err != nil {
					return nil, fmt.Errorf("inspect %s for secret %q: %w", name, item.Name, err)
				}
				found = found || matched
			}
		}
		if !found {
			continue
		}
		if !secure {
			return nil, fmt.Errorf("secret %q cannot be used over plaintext HTTP", item.Name)
		}
		if !slices.Contains(item.Clients, client) {
			return nil, fmt.Errorf("secret %q is not authorized for client %q", item.Name, client)
		}
		if !matchesHost(item.AllowedHosts, host) {
			return nil, fmt.Errorf("secret %q is not authorized for host %q", item.Name, host)
		}
		used[item.Name] = struct{}{}
	}

	// Apply all authorized replacements to a private copy before publishing
	// them to the request. Staging also preserves multiple substitutions in a
	// single header value, such as two Basic-auth credential components.
	staged := make(http.Header, len(req.Header))
	for name, values := range req.Header {
		staged[name] = append([]string(nil), values...)
	}
	for _, item := range b.secrets {
		for name, values := range staged {
			for i, value := range values {
				replaced, matched, err := replaceHeaderValue(name, value, item.Placeholder, item.value)
				if err != nil {
					return nil, fmt.Errorf("inspect %s for secret %q: %w", name, item.Name, err)
				}
				if matched {
					values[i] = replaced
				}
			}
		}
	}
	maps.Copy(req.Header, staged)
	names := make([]string, 0, len(used))
	for name := range used {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func replaceHeaderValue(name, value, placeholder, secret string) (string, bool, error) {
	if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Proxy-Authorization") {
		scheme, credential, ok := strings.Cut(strings.TrimSpace(value), " ")
		if !ok {
			if strings.Contains(value, placeholder) {
				return value, false, errors.New("placeholder must be a complete authorization credential")
			}
			return value, false, nil
		}
		credential = strings.TrimSpace(credential)
		if strings.EqualFold(scheme, "Basic") {
			decoded, err := base64.StdEncoding.DecodeString(credential)
			if err != nil {
				decoded, err = base64.RawStdEncoding.DecodeString(credential)
			}
			if err != nil {
				if strings.Contains(value, placeholder) {
					return value, false, errors.New("placeholder appears in malformed Basic credentials")
				}
				return value, false, nil
			}
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) != 2 && strings.Contains(string(decoded), placeholder) {
				return value, false, errors.New("basic credentials must contain username and password")
			}
			matched := false
			for i := range parts {
				if strings.Contains(parts[i], placeholder) {
					if parts[i] != placeholder {
						return value, false, errors.New("placeholder must occupy a complete Basic credential component")
					}
					parts[i] = secret
					matched = true
				}
			}
			if matched {
				return "Basic " + base64.StdEncoding.EncodeToString([]byte(strings.Join(parts, ":"))), true, nil
			}
			return value, false, nil
		}
		if credential == placeholder {
			return scheme + " " + secret, true, nil
		}
		if strings.Contains(value, placeholder) {
			return value, false, errors.New("placeholder must be a complete authorization credential")
		}
		return value, false, nil
	}
	if value == placeholder {
		return secret, true, nil
	}
	if strings.Contains(value, placeholder) {
		return value, false, errors.New("placeholder must occupy the complete header value")
	}
	return value, false, nil
}

func validName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		if unicode.IsLower(r) || (i > 0 && unicode.IsDigit(r)) || (i > 0 && r == '_') {
			continue
		}
		return false
	}
	return true
}

func normalizePattern(pattern string) (string, error) {
	pattern = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(pattern, ".")))
	host := strings.TrimPrefix(pattern, "*.")
	if host == "" || strings.ContainsAny(host, "*/:@") || strings.Contains(host, "..") {
		return "", fmt.Errorf("invalid host pattern %q", pattern)
	}
	if strings.HasPrefix(pattern, "*.") {
		return "*." + host, nil
	}
	return host, nil
}

func matchesHost(patterns []string, host string) bool {
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
