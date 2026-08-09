package oauth

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

const authVersion = 1

// substitutionSite distinguishes credential-carrying request locations from
// agent-authored content.
type substitutionSite int

const (
	siteCredential substitutionSite = iota // headers and query values
	siteBody                               // request bodies and WebSocket text
)

// Broker stores virtual-to-real OAuth token mappings and persists them in an
// operator-controlled auth file. The file is deliberately plaintext for the
// current development deployment and must not be mounted into a sandbox.
type Broker struct {
	mu       sync.RWMutex
	defs     []Definition
	byName   map[string]Definition
	authPath string
	records  map[string]tokenRecord
	virtual  map[string]tokenReference
}

type authFile struct {
	Version int           `json:"version"`
	Tokens  []tokenRecord `json:"tokens"`
}

type tokenRecord struct {
	Broker             string     `json:"broker"`
	Client             string     `json:"client"`
	IssuerHost         string     `json:"issuer_host"`
	AccessToken        string     `json:"access_token"`
	RefreshToken       string     `json:"refresh_token,omitempty"`
	AccessPlaceholder  string     `json:"access_placeholder"`
	RefreshPlaceholder string     `json:"refresh_placeholder,omitempty"`
	AccessExpiresAt    *time.Time `json:"access_expires_at,omitempty"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

type tokenReference struct {
	key  string
	kind string
}

// New validates policy and loads existing plaintext OAuth state.
func New(file File, authPath string) (*Broker, error) {
	if err := file.validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(authPath) == "" {
		return nil, errors.New("OAuth auth file path is required")
	}
	broker := &Broker{
		defs:     append([]Definition(nil), file.Brokers...),
		byName:   make(map[string]Definition, len(file.Brokers)),
		authPath: authPath,
		records:  make(map[string]tokenRecord),
		virtual:  make(map[string]tokenReference),
	}
	for _, definition := range file.Brokers {
		broker.byName[definition.Name] = definition
	}
	if err := broker.loadState(); err != nil {
		return nil, err
	}
	return broker, nil
}

// Apply substitutes virtual tokens found in request headers.
func (b *Broker) Apply(req *http.Request, client, host string, secure bool) ([]string, error) {
	if b == nil || req == nil {
		return nil, nil
	}
	used := make(map[string]struct{})
	for name, values := range req.Header {
		for index, value := range values {
			replaced, names, err := b.replaceRequestValue(value, client, host, secure, siteCredential, true)
			if err != nil {
				return nil, fmt.Errorf("inspect %s: %w", name, err)
			}
			values[index] = replaced
			for _, tokenName := range names {
				used[tokenName] = struct{}{}
			}
		}
		req.Header[name] = values
	}
	return sortedNames(used), nil
}

// SubstituteQuery substitutes exact virtual token query values.
func (b *Broker) SubstituteQuery(target *url.URL, client, host string, secure bool) ([]string, error) {
	if b == nil || target == nil || target.RawQuery == "" {
		return nil, nil
	}
	values, err := url.ParseQuery(target.RawQuery)
	if err != nil {
		return nil, errors.New("query string is malformed")
	}
	used := make(map[string]struct{})
	for name, entries := range values {
		if b.containsPlaceholder([]byte(name)) {
			return nil, errors.New("OAuth token placeholders are not allowed in query names")
		}
		for index, value := range entries {
			replaced, tokenName, err := b.replaceExact(value, client, host, secure, siteCredential)
			if err != nil {
				return nil, err
			}
			entries[index] = replaced
			if tokenName != "" {
				used[tokenName] = struct{}{}
			}
		}
	}
	target.RawQuery = values.Encode()
	return sortedNames(used), nil
}

// SubstituteBody substitutes exact virtual token values in JSON and form
// bodies. The broker does not alter unsupported media types.
//
// Bodies are substituted only for configured issuer hosts, so requests to API
// hosts are left untouched and are never parsed on the broker's behalf. That
// keeps a body the broker would not modify from failing the request, including
// non-JSON WebSocket text that merely carries an inert placeholder.
func (b *Broker) SubstituteBody(contentType string, body []byte, client, host string, secure bool) ([]byte, []string, bool, error) {
	if b == nil || len(body) == 0 || !b.issuerHost(host) {
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
		value, err := b.transformJSON(value, client, host, secure, used)
		if err != nil {
			return nil, nil, true, err
		}
		if len(used) == 0 {
			return body, nil, true, nil
		}
		transformed, err := json.Marshal(value)
		if err != nil {
			return nil, nil, true, fmt.Errorf("encode OAuth request body: %w", err)
		}
		return transformed, sortedNames(used), true, nil
	case mediaType == "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, nil, true, errors.New("form request body is malformed")
		}
		used := make(map[string]struct{})
		for name, entries := range values {
			if b.containsPlaceholder([]byte(name)) {
				return nil, nil, true, errors.New("OAuth token placeholders are not allowed in form names")
			}
			for index, value := range entries {
				replaced, tokenName, err := b.replaceExact(value, client, host, secure, siteBody)
				if err != nil {
					return nil, nil, true, err
				}
				entries[index] = replaced
				if tokenName != "" {
					used[tokenName] = struct{}{}
				}
			}
		}
		if len(used) == 0 {
			return body, nil, true, nil
		}
		return []byte(values.Encode()), sortedNames(used), true, nil
	default:
		// Reached only for issuer hosts, where an unsubstitutable token in the
		// body means the request cannot be mediated and must fail closed.
		if b.ContainsPlaceholder(body) {
			return nil, nil, false, errors.New("OAuth token placeholder appears in an unsupported request body")
		}
		return body, nil, false, nil
	}
}

// SubstituteJSONMessage substitutes virtual tokens in an outbound WebSocket
// JSON text message.
func (b *Broker) SubstituteJSONMessage(body []byte, client, host string) ([]byte, []string, error) {
	transformed, names, _, err := b.SubstituteBody("application/json", body, client, host, true)
	return transformed, names, err
}

// ObserveTokenResponse virtualizes configured access and refresh fields in a
// successful OAuth token response and persists the real values.
func (b *Broker) ObserveTokenResponse(req *http.Request, resp *http.Response, body []byte, client, host string) ([]byte, []string, error) {
	if b == nil || req == nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return body, nil, nil
	}
	definition, ok := b.matchDefinition(client, host, req.URL.Path)
	if !ok {
		return body, nil, nil
	}
	if mediaType := parseMediaType(resp.Header.Get("Content-Type")); mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json") {
		return nil, nil, errors.New("configured OAuth token response is not JSON")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, nil, errors.New("configured OAuth token response is malformed JSON")
	}
	access, ok := jsonString(fields[definition.AccessTokenField])
	if !ok || access == "" {
		return nil, nil, fmt.Errorf("configured OAuth response lacks %s", definition.AccessTokenField)
	}
	refresh, hasRefresh := jsonString(fields[definition.RefreshTokenField])
	if raw, exists := fields[definition.RefreshTokenField]; exists && string(raw) != "null" && (!hasRefresh || raw == nil) {
		return nil, nil, fmt.Errorf("configured OAuth field %s is not a string", definition.RefreshTokenField)
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	key := definition.Name + "\x00" + client
	old := b.records[key]
	accessPlaceholder, err := newAccessPlaceholder(access)
	if err != nil {
		return nil, nil, err
	}
	refreshPlaceholder := ""
	if hasRefresh && refresh != "" {
		refreshPlaceholder, err = newPlaceholder("REFRESH")
		if err != nil {
			return nil, nil, err
		}
	} else if old.RefreshToken != "" && old.RefreshPlaceholder != "" {
		// OAuth refresh responses may omit refresh_token when rotation is not
		// used. Preserve the existing virtual refresh token in that case.
		refresh = old.RefreshToken
		refreshPlaceholder = old.RefreshPlaceholder
		hasRefresh = true
	}
	record := tokenRecord{
		Broker:             definition.Name,
		Client:             client,
		IssuerHost:         definition.IssuerHost,
		AccessToken:        access,
		RefreshToken:       refresh,
		AccessPlaceholder:  accessPlaceholder,
		RefreshPlaceholder: refreshPlaceholder,
		AccessExpiresAt:    tokenExpiry(fields["expires_in"], fields["expires_at"]),
		UpdatedAt:          time.Now().UTC(),
	}
	if old.AccessPlaceholder != "" {
		delete(b.virtual, old.AccessPlaceholder)
	}
	if old.RefreshPlaceholder != "" {
		delete(b.virtual, old.RefreshPlaceholder)
	}
	b.records[key] = record
	b.virtual[record.AccessPlaceholder] = tokenReference{key: key, kind: "access"}
	if record.RefreshPlaceholder != "" {
		b.virtual[record.RefreshPlaceholder] = tokenReference{key: key, kind: "refresh"}
	}
	if err := b.writeStateLocked(); err != nil {
		return nil, nil, err
	}

	fields[definition.AccessTokenField] = json.RawMessage(mustJSON(accessPlaceholder))
	if hasRefresh && refreshPlaceholder != "" {
		fields[definition.RefreshTokenField] = json.RawMessage(mustJSON(refreshPlaceholder))
	}
	transformed, err := json.Marshal(fields)
	if err != nil {
		return nil, nil, fmt.Errorf("encode virtual OAuth token response: %w", err)
	}
	names := []string{oauthName(definition.Name, "access")}
	if refreshPlaceholder != "" {
		names = append(names, oauthName(definition.Name, "refresh"))
	}
	return transformed, names, nil
}

// Scrub replaces real OAuth token values with virtual values before delivery.
func (b *Broker) Scrub(data []byte, client, host string) ([]byte, []string) {
	if b == nil || len(data) == 0 {
		return data, nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := append([]byte(nil), data...)
	used := make(map[string]struct{})
	for _, record := range b.records {
		definition, ok := b.byName[record.Broker]
		if !ok || record.Client != client || !tokenHostAllowed(definition, "access", host) && !tokenHostAllowed(definition, "refresh", host) {
			continue
		}
		if record.AccessToken != "" && bytes.Contains(out, []byte(record.AccessToken)) {
			out = bytes.ReplaceAll(out, []byte(record.AccessToken), []byte(record.AccessPlaceholder))
			used[oauthName(record.Broker, "access")] = struct{}{}
		}
		if record.RefreshToken != "" && bytes.Contains(out, []byte(record.RefreshToken)) {
			out = bytes.ReplaceAll(out, []byte(record.RefreshToken), []byte(record.RefreshPlaceholder))
			used[oauthName(record.Broker, "refresh")] = struct{}{}
		}
	}
	return out, sortedNames(used)
}

// Sanitize replaces real and virtual OAuth tokens with safe metadata markers.
func (b *Broker) Sanitize(data []byte) []byte {
	if b == nil || len(data) == 0 {
		return append([]byte(nil), data...)
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := append([]byte(nil), data...)
	for _, record := range b.records {
		for _, value := range []string{record.AccessToken, record.AccessPlaceholder} {
			if value != "" {
				out = bytes.ReplaceAll(out, []byte(value), []byte("[secret:"+oauthName(record.Broker, "access")+"]"))
			}
		}
		for _, value := range []string{record.RefreshToken, record.RefreshPlaceholder} {
			if value != "" {
				out = bytes.ReplaceAll(out, []byte(value), []byte("[secret:"+oauthName(record.Broker, "refresh")+"]"))
			}
		}
	}
	return out
}

// ContainsPlaceholder reports whether data carries a live virtual OAuth token.
// Unknown placeholder-shaped text is not secret material, so it is ignored.
func (b *Broker) ContainsPlaceholder(data []byte) bool {
	if b == nil {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.containsKnownPlaceholderLocked(data)
}

// replaceRequestValue substitutes virtual tokens found in value.
//
// siteCredential covers headers and query values, the only locations where a
// placeholder can mean a credential: placeholder-shaped values that resolve to
// no live token are rejected so stale or forged tokens fail closed.
//
// siteBody covers request bodies and WebSocket text, which carry agent content
// that may legitimately quote placeholder text. A token belongs in a body only
// in the refresh request to the configured issuer, so substitution is confined
// to issuer hosts; elsewhere the placeholder is forwarded verbatim and inert.
func (b *Broker) replaceRequestValue(value, client, host string, secure bool, site substitutionSite, allowScheme bool) (string, []string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if site == siteBody && !b.isIssuerHostLocked(host) {
		return value, nil, nil
	}
	present := b.containsKnownPlaceholderLocked([]byte(value))
	if site == siteCredential && !present {
		present = oauthPlaceholderPattern.MatchString(value) ||
			virtualJWTPlaceholderInCredential(value, allowScheme)
	}
	if !present {
		return value, nil, nil
	}
	if site == siteCredential && !b.validCredentialValueLocked(value, allowScheme) {
		return value, nil, errors.New("OAuth token placeholder must occupy a complete credential value")
	}
	if !secure {
		return value, nil, errors.New("OAuth token cannot be used over plaintext HTTP")
	}
	used := make(map[string]struct{})
	out := value
	for placeholder, reference := range b.virtual {
		if !strings.Contains(out, placeholder) {
			continue
		}
		record, ok := b.records[reference.key]
		if !ok || record.Client != client {
			return value, nil, errors.New("OAuth token is not authorized for this client")
		}
		definition := b.byName[record.Broker]
		if !tokenHostAllowed(definition, reference.kind, host) {
			return value, nil, errors.New("OAuth token is not authorized for this host")
		}
		if reference.kind == "access" && record.AccessExpiresAt != nil && time.Now().After(*record.AccessExpiresAt) {
			return value, nil, errors.New("OAuth access token is expired")
		}
		replacement := record.AccessToken
		name := oauthName(record.Broker, "access")
		if reference.kind == "refresh" {
			replacement = record.RefreshToken
			name = oauthName(record.Broker, "refresh")
		}
		if replacement == "" {
			return value, nil, errors.New("OAuth token is unavailable")
		}
		out = strings.ReplaceAll(out, placeholder, replacement)
		used[name] = struct{}{}
	}
	if site == siteCredential && (oauthPlaceholderPattern.MatchString(out) ||
		virtualJWTPlaceholderInCredential(out, allowScheme)) {
		return value, nil, errors.New("unknown OAuth token placeholder")
	}
	return out, sortedNames(used), nil
}

func (b *Broker) replaceExact(value, client, host string, secure bool, site substitutionSite) (string, string, error) {
	replaced, names, err := b.replaceRequestValue(value, client, host, secure, site, false)
	if err != nil {
		return value, "", err
	}
	if len(names) == 0 {
		return value, "", nil
	}
	if replaced == value {
		return value, "", nil
	}
	return replaced, names[0], nil
}

func (b *Broker) transformJSON(value any, client, host string, secure bool, used map[string]struct{}) (any, error) {
	switch typed := value.(type) {
	case string:
		replaced, name, err := b.replaceExact(typed, client, host, secure, siteBody)
		if err != nil {
			return nil, err
		}
		if name != "" {
			used[name] = struct{}{}
		}
		return replaced, nil
	case []any:
		for index, child := range typed {
			replaced, err := b.transformJSON(child, client, host, secure, used)
			if err != nil {
				return nil, err
			}
			typed[index] = replaced
		}
		return typed, nil
	case map[string]any:
		for name, child := range typed {
			if b.containsPlaceholder([]byte(name)) {
				return nil, errors.New("OAuth token placeholders are not allowed in JSON field names")
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

func (b *Broker) matchDefinition(client, host, requestPath string) (Definition, bool) {
	for _, definition := range b.defs {
		if slices.Contains(definition.Clients, client) && definition.IssuerHost == strings.ToLower(strings.TrimSuffix(host, ".")) && definition.TokenPath == requestPath {
			return definition, true
		}
	}
	return Definition{}, false
}

// PlaceholderNames reports the virtual-token names present in data. It exposes
// names only, never token values, so rejections can be attributed in captures
// and audit records.
func (b *Broker) PlaceholderNames(data []byte) []string {
	if b == nil {
		return nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	used := make(map[string]struct{})
	for placeholder, reference := range b.virtual {
		if !bytes.Contains(data, []byte(placeholder)) {
			continue
		}
		if record, ok := b.records[reference.key]; ok {
			used[oauthName(record.Broker, reference.kind)] = struct{}{}
		}
	}
	return sortedNames(used)
}

func (b *Broker) issuerHost(host string) bool {
	if b == nil {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.isIssuerHostLocked(host)
}

func (b *Broker) containsPlaceholder(data []byte) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.containsPlaceholderLocked(data)
}

func (b *Broker) containsPlaceholderLocked(data []byte) bool {
	if oauthPlaceholderPattern.Match(data) {
		return true
	}
	return b.containsKnownPlaceholderLocked(data)
}

// isIssuerHostLocked reports whether host is a configured OAuth token endpoint
// host, the only destination where a placeholder legitimately travels in a body.
func (b *Broker) isIssuerHostLocked(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, definition := range b.defs {
		if definition.IssuerHost == host {
			return true
		}
	}
	return false
}

func (b *Broker) containsKnownPlaceholderLocked(data []byte) bool {
	for placeholder := range b.virtual {
		if bytes.Contains(data, []byte(placeholder)) {
			return true
		}
	}
	return false
}

func (b *Broker) validCredentialValueLocked(value string, allowScheme bool) bool {
	trimmed := strings.TrimSpace(value)
	candidates := []string{trimmed}
	if allowScheme {
		if _, credential, ok := strings.Cut(trimmed, " "); ok {
			candidates = append(candidates, strings.TrimSpace(credential))
		}
	}
	known := b.containsKnownPlaceholderLocked([]byte(value))
	for _, candidate := range candidates {
		if reference, ok := b.virtual[candidate]; ok && reference.key != "" {
			return true
		}
		if !known && (oauthPlaceholderPattern.FindString(candidate) == candidate || isVirtualJWTPlaceholder(candidate)) {
			return true
		}
	}
	return false
}

func (b *Broker) loadState() error {
	info, err := os.Lstat(b.authPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect OAuth auth file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("OAuth auth file must not be a symbolic link")
	}
	if err := os.Chmod(b.authPath, 0o600); err != nil {
		return fmt.Errorf("secure OAuth auth file: %w", err)
	}
	data, err := os.ReadFile(b.authPath)
	if err != nil {
		return fmt.Errorf("read OAuth auth file: %w", err)
	}
	var state authFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return fmt.Errorf("decode OAuth auth file: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("decode OAuth auth file: trailing JSON data")
	}
	if state.Version != authVersion {
		return fmt.Errorf("unsupported OAuth auth file version %d", state.Version)
	}
	for _, record := range state.Tokens {
		definition, ok := b.byName[record.Broker]
		if !ok || !slices.Contains(definition.Clients, record.Client) || record.AccessToken == "" || record.AccessPlaceholder == "" {
			return errors.New("OAuth auth file contains a token outside current policy")
		}
		key := record.Broker + "\x00" + record.Client
		if _, exists := b.records[key]; exists || b.virtual[record.AccessPlaceholder].key != "" {
			return errors.New("OAuth auth file contains duplicate token state")
		}
		b.records[key] = record
		b.virtual[record.AccessPlaceholder] = tokenReference{key: key, kind: "access"}
		if record.RefreshPlaceholder != "" {
			if record.RefreshToken == "" || b.virtual[record.RefreshPlaceholder].key != "" {
				return errors.New("OAuth auth file contains invalid refresh token state")
			}
			b.virtual[record.RefreshPlaceholder] = tokenReference{key: key, kind: "refresh"}
		}
	}
	return nil
}

func (b *Broker) writeStateLocked() error {
	state := authFile{Version: authVersion, Tokens: make([]tokenRecord, 0, len(b.records))}
	for _, record := range b.records {
		state.Tokens = append(state.Tokens, record)
	}
	sort.Slice(state.Tokens, func(i, j int) bool {
		if state.Tokens[i].Broker == state.Tokens[j].Broker {
			return state.Tokens[i].Client < state.Tokens[j].Client
		}
		return state.Tokens[i].Broker < state.Tokens[j].Broker
	})
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode OAuth auth state: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(b.authPath), 0o750); err != nil {
		return fmt.Errorf("create OAuth auth directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(b.authPath), ".auth-*.tmp")
	if err != nil {
		return fmt.Errorf("create OAuth auth temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure OAuth auth temporary file: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write OAuth auth state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync OAuth auth state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close OAuth auth state: %w", err)
	}
	if err := os.Rename(temporaryName, b.authPath); err != nil {
		return fmt.Errorf("replace OAuth auth state: %w", err)
	}
	return nil
}

func tokenHostAllowed(definition Definition, kind, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if kind == "refresh" {
		return host == definition.IssuerHost
	}
	return matchesHost(definition.APIHosts, host)
}

func tokenExpiry(raws ...json.RawMessage) *time.Time {
	for _, raw := range raws {
		if len(raw) == 0 || string(raw) == "null" {
			continue
		}
		var val int64
		if err := json.Unmarshal(raw, &val); err == nil && val > 0 {
			t := parseTimeInt(val)
			return &t
		}
		var str string
		if err := json.Unmarshal(raw, &str); err == nil && str != "" {
			if _, err := fmt.Sscan(str, &val); err == nil && val > 0 {
				t := parseTimeInt(val)
				return &t
			}
			if parsed, err := time.Parse(time.RFC3339, str); err == nil {
				utc := parsed.UTC()
				return &utc
			}
		}
	}
	return nil
}

func parseTimeInt(val int64) time.Time {
	now := time.Now().UTC()
	switch {
	case val < 1_000_000_000:
		return now.Add(time.Duration(val) * time.Second)
	case val < 100_000_000_000:
		return time.Unix(val, 0).UTC()
	default:
		return time.UnixMilli(val).UTC()
	}
}

func jsonString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}

func newAccessPlaceholder(realToken string) (string, error) {
	if isJWT(realToken) {
		virtualJWT, err := makeVirtualJWT(realToken)
		if err == nil {
			return virtualJWT, nil
		}
	}
	if strings.Contains(realToken, "sk-ant-oat") {
		return newPlaceholder("ACCESS_sk-ant-oat")
	}
	return newPlaceholder("ACCESS")
}

func isJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || slices.Contains(parts, "") {
		return false
	}
	header, err := decodeBase64URL(parts[0])
	if err != nil || !json.Valid(header) {
		return false
	}
	payload, err := decodeBase64URL(parts[1])
	return err == nil && json.Valid(payload)
}

func isVirtualJWTPlaceholder(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || slices.Contains(parts, "") {
		return false
	}
	payload, err := decodeBase64URL(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		VeilgateID string `json:"_veilgate_id"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return false
	}
	return claims.VeilgateID != "" && oauthPlaceholderPattern.FindString(claims.VeilgateID) == claims.VeilgateID
}

func virtualJWTPlaceholderInCredential(value string, allowScheme bool) bool {
	value = strings.TrimSpace(value)
	if isVirtualJWTPlaceholder(value) {
		return true
	}
	if allowScheme {
		if _, credential, ok := strings.Cut(value, " "); ok {
			return isVirtualJWTPlaceholder(strings.TrimSpace(credential))
		}
	}
	return false
}

func makeVirtualJWT(realJWT string) (string, error) {
	parts := strings.Split(realJWT, ".")
	if len(parts) != 3 {
		return "", errors.New("not a 3-part JWT")
	}
	headerBytes, err := decodeBase64URL(parts[0])
	if err != nil {
		return "", err
	}
	payloadBytes, err := decodeBase64URL(parts[1])
	if err != nil {
		return "", err
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return "", err
	}
	idBytes := make([]byte, 24)
	if _, err := rand.Read(idBytes); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)
	payload["_veilgate_id"] = json.RawMessage(mustJSON("VEILGATED_SECRET_OAUTH_ACCESS_" + id))

	newPayloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerBytes)
	encodedPayload := base64.RawURLEncoding.EncodeToString(newPayloadBytes)
	dummySig := base64.RawURLEncoding.EncodeToString([]byte("veilgate_dummy_signature_" + id))

	return encodedHeader + "." + encodedPayload + "." + dummySig, nil
}

func decodeBase64URL(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

func newPlaceholder(kind string) (string, error) {
	bytesValue := make([]byte, 24)
	if _, err := rand.Read(bytesValue); err != nil {
		return "", fmt.Errorf("generate OAuth placeholder: %w", err)
	}
	return "VEILGATED_SECRET_OAUTH_" + kind + "_" + base64.RawURLEncoding.EncodeToString(bytesValue), nil
}

func mustJSON(value string) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

const oauthPlaceholderPrefix = "VEILGATED_SECRET_OAUTH_"

// oauthPlaceholderPattern matches the full generated placeholder shape rather
// than the bare prefix, so documentation and source text that merely mention
// the prefix are not mistaken for tokens.
var oauthPlaceholderPattern = regexp.MustCompile(oauthPlaceholderPrefix + `(?:ACCESS|REFRESH)_[A-Za-z0-9_-]{32,}`)

func oauthName(broker, kind string) string { return "oauth_" + broker + "_" + kind + "_token" }

func sortedNames(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func parseMediaType(contentType string) string {
	value := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	return value
}

func supportedMediaType(contentType string) bool {
	value := parseMediaType(contentType)
	return value == "application/json" || strings.HasSuffix(value, "+json") || value == "application/x-www-form-urlencoded"
}
