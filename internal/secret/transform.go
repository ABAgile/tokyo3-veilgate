package secret

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/url"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

// SubstituteQuery replaces exact placeholder query values after enforcing the
// secret's client and host scope. Placeholders in names or embedded inside a
// larger value fail closed.
func (b *Broker) SubstituteQuery(u *url.URL, client, host string, secure bool) ([]string, error) {
	if b == nil || u == nil || u.RawQuery == "" {
		return nil, nil
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, errors.New("query string is malformed")
	}
	used := make(map[string]struct{})
	for name, entries := range values {
		if b.ContainsPlaceholder([]byte(name)) {
			return nil, errors.New("secret placeholders are not allowed in query names")
		}
		for i, value := range entries {
			replaced, item, err := b.substituteExact(value, client, host, secure)
			if err != nil {
				return nil, err
			}
			entries[i] = replaced
			if item != nil {
				used[item.Name] = struct{}{}
			}
		}
	}
	names := sortedNames(used)
	if len(names) > 0 {
		u.RawQuery = values.Encode()
	}
	return names, nil
}

// SubstituteBody replaces exact placeholders in JSON string values or form
// values. Embedded placeholder text in those values remains ordinary content.
// The boolean reports whether the media type is safe for text capture.
// Unsupported bodies containing a known placeholder fail closed.
func (b *Broker) SubstituteBody(contentType string, body []byte, client, host string, secure bool) ([]byte, []string, bool, error) {
	if len(body) == 0 {
		return body, nil, supportedMediaType(contentType), nil
	}
	mediaType := parseMediaType(contentType)
	switch {
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		var value any
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return nil, nil, true, errors.New("JSON request body is malformed")
		}
		if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
			return nil, nil, true, errors.New("JSON request body contains trailing data")
		}
		used := make(map[string]struct{})
		transformed, err := b.transformJSON(value, client, host, secure, used)
		if err != nil {
			return nil, nil, true, err
		}
		names := sortedNames(used)
		if len(names) == 0 {
			return body, nil, true, nil
		}
		encoded, err := json.Marshal(transformed)
		if err != nil {
			return nil, nil, true, fmt.Errorf("encode transformed JSON: %w", err)
		}
		return encoded, names, true, nil
	case mediaType == "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, nil, true, errors.New("form request body is malformed")
		}
		used := make(map[string]struct{})
		for name, entries := range values {
			if b.ContainsPlaceholder([]byte(name)) {
				return nil, nil, true, errors.New("secret placeholders are not allowed in form names")
			}
			for i, value := range entries {
				replaced, item, err := b.substituteBodyValue(value, client, host, secure)
				if err != nil {
					return nil, nil, true, err
				}
				entries[i] = replaced
				if item != nil {
					used[item.Name] = struct{}{}
				}
			}
		}
		names := sortedNames(used)
		if len(names) == 0 {
			return body, nil, true, nil
		}
		return []byte(values.Encode()), names, true, nil
	default:
		if b.ContainsPlaceholder(body) {
			return nil, nil, false, errors.New("secret placeholder appears in an unsupported request body")
		}
		return body, nil, false, nil
	}
}

// SubstituteJSONMessage transforms exact placeholders in one WebSocket JSON
// text message. Non-JSON text messages fail closed.
func (b *Broker) SubstituteJSONMessage(message []byte, client, host string) ([]byte, []string, error) {
	body, names, _, err := b.SubstituteBody("application/json", message, client, host, true)
	return body, names, err
}

// Scrub replaces authorized host secret values with their opaque placeholders
// before response data is returned to the sandbox. Replacement is single-pass,
// so generated placeholders are never recursively interpreted as values.
func (b *Broker) Scrub(data []byte, client, host string) ([]byte, []string) {
	if b == nil || len(data) == 0 {
		return data, nil
	}
	scope := b.scopeFor(client, host)
	var out bytes.Buffer
	out.Grow(len(data))
	used := make(map[string]struct{})
	copied := 0
	for offset := 0; offset < len(data); {
		length, secret, masked := b.trie.longest(data[offset:], kindValue, scope)
		if length == 0 {
			length, secret = b.maskedAt(data[offset:], masked, scope)
		}
		if length == 0 {
			offset++
			continue
		}
		out.Write(data[copied:offset])
		out.Write(b.secrets[secret].placeholderBytes)
		used[b.secrets[secret].Name] = struct{}{}
		offset += length
		copied = offset
	}
	out.Write(data[copied:])
	return out.Bytes(), sortedNames(used)
}

// scopeFor marks the secrets authorized for one client and host, so the
// matcher can share a single trie across every scope instead of rebuilding a
// pattern set per request.
func (b *Broker) scopeFor(client, host string) []bool {
	scope := make([]bool, len(b.secrets))
	for i := range b.secrets {
		item := &b.secrets[i]
		scope[i] = slices.Contains(item.Clients, client) && matchesHost(item.AllowedHosts, host)
	}
	return scope
}

// maskedAt resolves a masked rendering at the current offset. Candidates are
// already in secret order, so the first match wins exactly as a scan over the
// configured secrets would.
func (b *Broker) maskedAt(data []byte, candidates []int, scope []bool) (int, int) {
	for _, secret := range candidates {
		if scope != nil && !scope[secret] {
			continue
		}
		if length := maskedSecretLength(data, b.secrets[secret].valueBytes); length > 0 {
			return length, secret
		}
	}
	return 0, 0
}

// Sanitize replaces every configured value and placeholder with a stable
// secret-name marker suitable for persistence and operator display.
func (b *Broker) Sanitize(data []byte) []byte {
	if b == nil || len(data) == 0 {
		return append([]byte(nil), data...)
	}
	var out bytes.Buffer
	out.Grow(len(data))
	copied := 0
	for offset := 0; offset < len(data); {
		length, secret, _ := b.trie.longest(data[offset:], kindValue|kindPlaceholder, nil)
		if length == 0 {
			offset++
			continue
		}
		out.Write(data[copied:offset])
		out.Write(b.secrets[secret].marker)
		offset += length
		copied = offset
	}
	out.Write(data[copied:])
	return out.Bytes()
}

// ContainsPlaceholder reports whether data includes any configured placeholder.
func (b *Broker) ContainsPlaceholder(data []byte) bool {
	if b == nil {
		return false
	}
	for _, item := range b.secrets {
		if bytes.Contains(data, []byte(item.Placeholder)) {
			return true
		}
	}
	return false
}

// PlaceholderNames reports the names of configured secrets whose placeholder
// appears in data. It exposes names only, never values, so rejections can be
// attributed in captures and audit records.
func (b *Broker) PlaceholderNames(data []byte) []string {
	if b == nil {
		return nil
	}
	var names []string
	for _, item := range b.secrets {
		if bytes.Contains(data, []byte(item.Placeholder)) {
			names = append(names, item.Name)
		}
	}
	return names
}

func (b *Broker) transformJSON(value any, client, host string, secure bool, used map[string]struct{}) (any, error) {
	switch typed := value.(type) {
	case string:
		replaced, item, err := b.substituteBodyValue(typed, client, host, secure)
		if item != nil {
			used[item.Name] = struct{}{}
		}
		return replaced, err
	case []any:
		for i, child := range typed {
			replaced, err := b.transformJSON(child, client, host, secure, used)
			if err != nil {
				return nil, err
			}
			typed[i] = replaced
		}
		return typed, nil
	case map[string]any:
		for name, child := range typed {
			if b.ContainsPlaceholder([]byte(name)) {
				return nil, errors.New("secret placeholders are not allowed in JSON object names")
			}
			replaced, err := b.transformJSON(child, client, host, secure, used)
			if err != nil {
				return nil, err
			}
			typed[name] = replaced
		}
		return typed, nil
	default:
		return typed, nil
	}
}

func (b *Broker) substituteExact(value, client, host string, secure bool) (string, *resolved, error) {
	return b.substituteValue(value, client, host, secure, true)
}

func (b *Broker) substituteBodyValue(value, client, host string, secure bool) (string, *resolved, error) {
	return b.substituteValue(value, client, host, secure, false)
}

func (b *Broker) substituteValue(value, client, host string, secure, rejectEmbedded bool) (string, *resolved, error) {
	for i := range b.secrets {
		item := &b.secrets[i]
		if value == item.Placeholder {
			if !secure {
				return value, nil, fmt.Errorf("secret %q cannot be used over plaintext HTTP", item.Name)
			}
			if !slices.Contains(item.Clients, client) {
				return value, nil, fmt.Errorf("secret %q is not authorized for client %q", item.Name, client)
			}
			if !matchesHost(item.AllowedHosts, host) {
				return value, nil, fmt.Errorf("secret %q is not authorized for host %q", item.Name, host)
			}
			return item.value, item, nil
		}
		if rejectEmbedded && strings.Contains(value, item.Placeholder) {
			return value, nil, fmt.Errorf("secret %q placeholder must occupy the complete value", item.Name)
		}
	}
	return value, nil, nil
}

func secretRepresentations(value string) [][]byte {
	jsonValue, _ := json.Marshal(value)
	candidates := []string{
		value,
		url.QueryEscape(value),
		url.PathEscape(value),
		strings.TrimSuffix(strings.TrimPrefix(string(jsonValue), `"`), `"`),
		base64.StdEncoding.EncodeToString([]byte(value)),
		base64.RawStdEncoding.EncodeToString([]byte(value)),
		base64.URLEncoding.EncodeToString([]byte(value)),
		base64.RawURLEncoding.EncodeToString([]byte(value)),
	}
	seen := make(map[string]struct{}, len(candidates))
	out := make([][]byte, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, []byte(candidate))
	}
	return out
}

func maskedSecretLength(data, value []byte) int {
	const minVisible = 4
	if len(value) < minVisible*2 {
		return 0
	}
	for prefixLength := min(16, len(value)-minVisible); prefixLength >= minVisible; prefixLength-- {
		if !bytes.HasPrefix(data, value[:prefixLength]) {
			continue
		}
		offset, masks := prefixLength, 0
		for offset < len(data) {
			r, size := utf8.DecodeRune(data[offset:])
			if r != '*' && r != 'x' && r != 'X' && r != '•' && r != '#' {
				break
			}
			offset += size
			masks++
		}
		if masks < 3 {
			continue
		}
		for suffixLength := min(8, len(value)-prefixLength); suffixLength >= minVisible; suffixLength-- {
			if bytes.HasPrefix(data[offset:], value[len(value)-suffixLength:]) {
				return offset + suffixLength
			}
		}
	}
	return 0
}

func sortedNames(names map[string]struct{}) []string {
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func parseMediaType(contentType string) string {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ""
	}
	return strings.ToLower(mediaType)
}

func supportedMediaType(contentType string) bool {
	mediaType := parseMediaType(contentType)
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json") || mediaType == "application/x-www-form-urlencoded"
}
