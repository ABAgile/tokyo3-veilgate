// Package oauth virtualizes configured OAuth access and refresh tokens for
// authenticated sandbox clients.
package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"strings"
)

// File is the OAuth broker policy document.
type File struct {
	Brokers []Definition `json:"brokers"`
}

// Definition identifies one token endpoint and the API hosts for its tokens.
type Definition struct {
	Name              string   `json:"name"`
	Clients           []string `json:"clients"`
	IssuerHost        string   `json:"issuer_host"`
	TokenPath         string   `json:"token_path"`
	APIHosts          []string `json:"api_hosts"`
	AccessTokenField  string   `json:"access_token_field,omitempty"`
	RefreshTokenField string   `json:"refresh_token_field,omitempty"`
}

// Load reads and validates an OAuth broker policy and its persisted state.
func Load(policyPath, authPath string) (*Broker, error) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("read OAuth policy: %w", err)
	}
	var file File
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("decode OAuth policy: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode OAuth policy: trailing JSON data")
	}
	return New(file, authPath)
}

func (f *File) validate() error {
	names := make(map[string]struct{}, len(f.Brokers))
	endpoints := make(map[string]struct{}, len(f.Brokers))
	for i := range f.Brokers {
		definition := &f.Brokers[i]
		definition.Name = strings.TrimSpace(definition.Name)
		if !validIdentifier(definition.Name) {
			return fmt.Errorf("brokers[%d].name is invalid", i)
		}
		if _, exists := names[definition.Name]; exists {
			return fmt.Errorf("duplicate OAuth broker name %q", definition.Name)
		}
		names[definition.Name] = struct{}{}
		if len(definition.Clients) == 0 {
			return fmt.Errorf("OAuth broker %q requires clients", definition.Name)
		}
		for j, client := range definition.Clients {
			definition.Clients[j] = strings.TrimSpace(client)
			if definition.Clients[j] == "" {
				return fmt.Errorf("OAuth broker %q clients[%d] is empty", definition.Name, j)
			}
		}
		issuer, err := normalizeHost(definition.IssuerHost, false)
		if err != nil {
			return fmt.Errorf("OAuth broker %q issuer_host: %w", definition.Name, err)
		}
		definition.IssuerHost = issuer
		definition.TokenPath, err = normalizeTokenPath(definition.TokenPath)
		if err != nil {
			return fmt.Errorf("OAuth broker %q token_path: %w", definition.Name, err)
		}
		if len(definition.APIHosts) == 0 {
			return fmt.Errorf("OAuth broker %q requires api_hosts", definition.Name)
		}
		for j, host := range definition.APIHosts {
			normalized, err := normalizeHost(host, true)
			if err != nil {
				return fmt.Errorf("OAuth broker %q api_hosts[%d]: %w", definition.Name, j, err)
			}
			definition.APIHosts[j] = normalized
		}
		if definition.AccessTokenField == "" {
			definition.AccessTokenField = "access_token"
		}
		if definition.RefreshTokenField == "" {
			definition.RefreshTokenField = "refresh_token"
		}
		if !validJSONField(definition.AccessTokenField) || !validJSONField(definition.RefreshTokenField) {
			return fmt.Errorf("OAuth broker %q token field is invalid", definition.Name)
		}
		for _, client := range definition.Clients {
			endpoint := client + "\x00" + definition.IssuerHost + "\x00" + definition.TokenPath
			if _, exists := endpoints[endpoint]; exists {
				return fmt.Errorf("duplicate OAuth token endpoint for client %q", client)
			}
			endpoints[endpoint] = struct{}{}
		}
	}
	return nil
}

func normalizeHost(value string, wildcard bool) (string, error) {
	value = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(value, ".")))
	isWildcard := wildcard && strings.HasPrefix(value, "*.")
	if isWildcard {
		value = strings.TrimPrefix(value, "*.")
	}
	if value == "" || strings.ContainsAny(value, ":/@* ") || strings.Contains(value, "..") || len(value) > 253 {
		return "", fmt.Errorf("invalid host %q", value)
	}
	for label := range strings.SplitSeq(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid host %q", value)
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", fmt.Errorf("invalid host %q", value)
			}
		}
	}
	if isWildcard {
		return "*." + value, nil
	}
	return value, nil
}

func normalizeTokenPath(value string) (string, error) {
	value = strings.TrimSpace(value)
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Path != value || !strings.HasPrefix(value, "/") || strings.Contains(value, "..") {
		return "", errors.New("must be an absolute path without query or traversal")
	}
	clean := path.Clean(value)
	if clean != value {
		return "", errors.New("must not contain redundant path segments")
	}
	return value, nil
}

func validIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9' && index > 0) || (character == '_' && index > 0) || (character >= 'A' && character <= 'Z' && index > 0) {
			continue
		}
		return false
	}
	return true
}

func validJSONField(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
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
