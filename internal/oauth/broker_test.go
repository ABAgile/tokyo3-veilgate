package oauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testOAuthFile() File {
	return File{Brokers: []Definition{{
		Name:       "example",
		Clients:    []string{"agent"},
		IssuerHost: "login.example.com",
		TokenPath:  "/oauth/token",
		APIHosts:   []string{"api.example.com"},
	}}}
}

func TestBrokerVirtualizesAndPersistsOAuthTokens(t *testing.T) {
	authPath := filepath.Join(t.TempDir(), "auth.json")
	broker, err := New(testOAuthFile(), authPath)
	if err != nil {
		t.Fatal(err)
	}
	tokenRequest, err := http.NewRequest(http.MethodPost, "https://login.example.com/oauth/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}}
	body := []byte(`{"access_token":"real-access-token","refresh_token":"real-refresh-token","token_type":"Bearer","expires_in":3600}`)
	virtual, names, err := broker.ObserveTokenResponse(tokenRequest, response, body, "agent", "login.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || strings.Contains(string(virtual), "real-access-token") || strings.Contains(string(virtual), "real-refresh-token") {
		t.Fatalf("virtual response = %s names = %#v", virtual, names)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(virtual, &fields); err != nil {
		t.Fatal(err)
	}
	var accessPlaceholder, refreshPlaceholder string
	if err := json.Unmarshal(fields["access_token"], &accessPlaceholder); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fields["refresh_token"], &refreshPlaceholder); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(accessPlaceholder, "VEILGATED_SECRET_OAUTH_ACCESS_") || !strings.HasPrefix(refreshPlaceholder, "VEILGATED_SECRET_OAUTH_REFRESH_") {
		t.Fatalf("virtual fields = %#v", fields)
	}
	info, err := os.Stat(authPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("auth permissions = %o", info.Mode().Perm())
	}
	persisted, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(persisted), "real-access-token") || !strings.Contains(string(persisted), "real-refresh-token") {
		t.Fatal("auth state did not persist real tokens")
	}

	loaded, err := New(testOAuthFile(), authPath)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+accessPlaceholder)
	used, err := loaded.Apply(request, "agent", "api.example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	if request.Header.Get("Authorization") != "Bearer real-access-token" || len(used) != 1 || used[0] != "oauth_example_access_token" {
		t.Fatalf("request = %q names = %#v", request.Header.Get("Authorization"), used)
	}

	refreshRequest, err := http.NewRequest(http.MethodPost, "https://login.example.com/oauth/token", strings.NewReader("grant_type=refresh_token&refresh_token="+url.QueryEscape(refreshPlaceholder)))
	if err != nil {
		t.Fatal(err)
	}
	refreshRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	transformed, used, supported, err := loaded.SubstituteBody(refreshRequest.Header.Get("Content-Type"), []byte("grant_type=refresh_token&refresh_token="+url.QueryEscape(refreshPlaceholder)), "agent", "login.example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	if !supported || string(transformed) != "grant_type=refresh_token&refresh_token=real-refresh-token" || len(used) != 1 || used[0] != "oauth_example_refresh_token" {
		t.Fatalf("refresh body = %q supported = %t names = %#v", transformed, supported, used)
	}
}

func TestBrokerRejectsEmbeddedCredentialPlaceholders(t *testing.T) {
	authPath := filepath.Join(t.TempDir(), "auth.json")
	broker, err := New(testOAuthFile(), authPath)
	if err != nil {
		t.Fatal(err)
	}
	tokenRequest, _ := http.NewRequest(http.MethodPost, "https://login.example.com/oauth/token", nil)
	response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}}
	virtual, _, err := broker.ObserveTokenResponse(tokenRequest, response, []byte(`{"access_token":"real-access-token","refresh_token":"real-refresh-token"}`), "agent", "login.example.com")
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]string
	if err := json.Unmarshal(virtual, &fields); err != nil {
		t.Fatal(err)
	}
	placeholder := fields["access_token"]

	request, _ := http.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	request.Header.Set("Authorization", "Bearer "+placeholder+"-suffix")
	if _, err := broker.Apply(request, "agent", "api.example.com", true); err == nil {
		t.Fatal("embedded OAuth header placeholder accepted")
	}

	query, err := url.Parse("https://api.example.com/v1?token=" + url.QueryEscape("prefix-"+placeholder))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.SubstituteQuery(query, "agent", "api.example.com", true); err == nil {
		t.Fatal("embedded OAuth query placeholder accepted")
	}
}

func TestBrokerPreservesAnthropicOAuthPrefix(t *testing.T) {
	authPath := filepath.Join(t.TempDir(), "auth.json")
	broker, err := New(testOAuthFile(), authPath)
	if err != nil {
		t.Fatal(err)
	}
	tokenRequest, _ := http.NewRequest(http.MethodPost, "https://login.example.com/oauth/token", nil)
	response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}}
	body := []byte(`{"access_token":"sk-ant-oat01-real-anthropic-oauth-token","token_type":"Bearer","expires_in":3600}`)

	virtualResp, _, err := broker.ObserveTokenResponse(tokenRequest, response, body, "agent", "login.example.com")
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(virtualResp, &fields); err != nil {
		t.Fatal(err)
	}
	var accessToken string
	if err := json.Unmarshal(fields["access_token"], &accessToken); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(accessToken, "sk-ant-oat") {
		t.Fatalf("access_token placeholder missing sk-ant-oat: %q", accessToken)
	}
}

func TestTokenExpirySupportsVariousFormats(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"relative seconds", `{"expires_in": 3600}`},
		{"epoch seconds", `{"expires_at": 2000000000}`},
		{"epoch ms", `{"expires_at": 2000000000000}`},
		{"iso string", `{"expires_at": "2030-01-01T00:00:00Z"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal([]byte(tc.raw), &fields); err != nil {
				t.Fatal(err)
			}
			exp := tokenExpiry(fields["expires_in"], fields["expires_at"])
			if exp == nil || exp.Before(time.Now().UTC()) {
				t.Fatalf("tokenExpiry(%s) = %v, expected future time", tc.raw, exp)
			}
		})
	}
}

func TestBrokerVirtualizesJWTWithPreservedClaims(t *testing.T) {
	authPath := filepath.Join(t.TempDir(), "auth.json")
	broker, err := New(testOAuthFile(), authPath)
	if err != nil {
		t.Fatal(err)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user_123","account_id":"acct_openai_99","iss":"https://auth.openai.com"}`))
	realJWT := header + "." + payload + ".real_signature_bytes_here"

	tokenRequest, _ := http.NewRequest(http.MethodPost, "https://login.example.com/oauth/token", nil)
	response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}}
	body := []byte(`{"access_token":"` + realJWT + `","token_type":"Bearer","expires_in":3600}`)

	virtualResp, names, err := broker.ObserveTokenResponse(tokenRequest, response, body, "agent", "login.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "oauth_example_access_token" {
		t.Fatalf("names = %#v", names)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(virtualResp, &fields); err != nil {
		t.Fatal(err)
	}
	var virtualJWT string
	if err := json.Unmarshal(fields["access_token"], &virtualJWT); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(virtualJWT, ".")
	if len(parts) != 3 {
		t.Fatalf("virtual token is not a 3-part JWT: %q", virtualJWT)
	}
	decodedPayloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode virtual payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(decodedPayloadBytes, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["account_id"] != "acct_openai_99" || claims["sub"] != "user_123" {
		t.Fatalf("claims missing in virtual JWT: %#v", claims)
	}
	if !strings.HasPrefix(claims["_veilgate_id"].(string), "VEILGATED_SECRET_OAUTH_ACCESS_") {
		t.Fatalf("tracking claim _veilgate_id missing or invalid: %#v", claims)
	}

	// Verify request replacement restores real JWT
	apiRequest, _ := http.NewRequest(http.MethodGet, "https://api.example.com/v1/models", nil)
	apiRequest.Header.Set("Authorization", "Bearer "+virtualJWT)
	used, err := broker.Apply(apiRequest, "agent", "api.example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(used) != 1 || used[0] != "oauth_example_access_token" {
		t.Fatalf("used = %#v", used)
	}
	if apiRequest.Header.Get("Authorization") != "Bearer "+realJWT {
		t.Fatalf("replaced header = %q, want Bearer %q", apiRequest.Header.Get("Authorization"), realJWT)
	}
}

func TestBrokerKeepsSecretScopeSeparateFromBroadDestinationPolicy(t *testing.T) {
	broker, err := New(testOAuthFile(), filepath.Join(t.TempDir(), "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://other.example/", nil)
	request.Header.Set("Authorization", "Bearer VEILGATED_SECRET_OAUTH_ACCESS_00000000000000000000000000000000")
	if _, err := broker.Apply(request, "agent", "other.example", true); err == nil {
		t.Fatal("unknown OAuth placeholder was accepted")
	}
}

func TestBrokerAllowsPlaceholderPrefixInContent(t *testing.T) {
	broker, err := New(testOAuthFile(), filepath.Join(t.TempDir(), "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Source text and documentation mention the prefix without carrying a token.
	body := []byte(`{"text":"const oauthPlaceholderPrefix = \"VEILGATED_SECRET_OAUTH_\"; payload = VEILGATED_SECRET_OAUTH_ACCESS_ + id"}`)
	transformed, used, _, err := broker.SubstituteBody("application/json", body, "agent", "api.example.com", true)
	if err != nil {
		t.Fatalf("prefix mention rejected: %v", err)
	}
	if len(used) != 0 || !bytes.Equal(transformed, body) {
		t.Fatalf("body altered: used = %#v, body = %s", used, transformed)
	}

	// Agent prompts quoting a full but unknown placeholder (test fixtures, logs,
	// rotated tokens) must not fail the request.
	stale := []byte(`{"text":"Bearer VEILGATED_SECRET_OAUTH_ACCESS_00000000000000000000000000000000"}`)
	transformed, used, _, err = broker.SubstituteBody("application/json", stale, "agent", "api.example.com", true)
	if err != nil {
		t.Fatalf("stale placeholder in content rejected: %v", err)
	}
	if len(used) != 0 || !bytes.Equal(transformed, stale) {
		t.Fatalf("body altered: used = %#v, body = %s", used, transformed)
	}

	// The same value in a header is still rejected.
	request, _ := http.NewRequest(http.MethodGet, "https://api.example.com/v1/models", nil)
	request.Header.Set("Authorization", "Bearer VEILGATED_SECRET_OAUTH_ACCESS_00000000000000000000000000000000")
	if _, err := broker.Apply(request, "agent", "api.example.com", true); err == nil {
		t.Fatal("unknown placeholder accepted in header")
	}
}

func TestBrokerConfinesBodySubstitutionToTokenEndpoint(t *testing.T) {
	broker, err := New(testOAuthFile(), filepath.Join(t.TempDir(), "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	tokenRequest, _ := http.NewRequest(http.MethodPost, "https://login.example.com/oauth/token", nil)
	response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}}
	virtual, _, err := broker.ObserveTokenResponse(tokenRequest, response, []byte(`{"access_token":"real-access-token","refresh_token":"real-refresh-token","token_type":"Bearer"}`), "agent", "login.example.com")
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]string
	if err := json.Unmarshal(virtual, &fields); err != nil {
		t.Fatal(err)
	}
	placeholder := fields["access_token"]

	// An agent that reads its own credential store and quotes a live placeholder
	// into a prompt must not have the real token spliced into the API body.
	prompt, err := json.Marshal(map[string]string{"prompt": "my token is " + placeholder})
	if err != nil {
		t.Fatal(err)
	}
	transformed, used, _, err := broker.SubstituteBody("application/json", prompt, "agent", "api.example.com", true)
	if err != nil {
		t.Fatalf("live placeholder in API body rejected: %v", err)
	}
	if len(used) != 0 || !bytes.Equal(transformed, prompt) {
		t.Fatalf("API body substituted: used = %#v, body = %s", used, transformed)
	}
	if bytes.Contains(transformed, []byte("real-access-token")) {
		t.Fatal("real token leaked into API request body")
	}

	// The header on the same host still resolves.
	apiRequest, _ := http.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	apiRequest.Header.Set("Authorization", "Bearer "+placeholder)
	if _, err := broker.Apply(apiRequest, "agent", "api.example.com", true); err != nil {
		t.Fatal(err)
	}
	if apiRequest.Header.Get("Authorization") != "Bearer real-access-token" {
		t.Fatalf("header = %q", apiRequest.Header.Get("Authorization"))
	}

	// A body sent to the issuer still resolves.
	issuerBody, err := json.Marshal(map[string]string{"grant_type": "refresh_token", "refresh_token": fields["refresh_token"]})
	if err != nil {
		t.Fatal(err)
	}
	transformed, used, _, err = broker.SubstituteBody("application/json", issuerBody, "agent", "login.example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(used) != 1 || !bytes.Contains(transformed, []byte("real-refresh-token")) {
		t.Fatalf("issuer body = %s used = %#v", transformed, used)
	}

	// A non-JSON WebSocket text message carrying an inert placeholder must not
	// fail the connection on a host where nothing would be substituted.
	message := []byte("ping " + placeholder)
	transformed, used, err = broker.SubstituteJSONMessage(message, "agent", "api.example.com")
	if err != nil {
		t.Fatalf("non-JSON WebSocket text rejected: %v", err)
	}
	if len(used) != 0 || !bytes.Equal(transformed, message) {
		t.Fatalf("message altered: used = %#v, message = %s", used, transformed)
	}

	// The issuer still rejects a body it cannot mediate.
	if _, _, err := broker.SubstituteJSONMessage(message, "agent", "login.example.com"); err == nil {
		t.Fatal("malformed issuer body accepted")
	}
}

func TestOAuthPolicyRejectsUnsafeDefinitions(t *testing.T) {
	for _, definition := range []Definition{
		{Name: "example", Clients: []string{"agent"}, IssuerHost: "login.example.com", TokenPath: "oauth/token", APIHosts: []string{"api.example.com"}},
		{Name: "example", Clients: []string{"agent"}, IssuerHost: "login.example.com", TokenPath: "/oauth/../token", APIHosts: []string{"api.example.com"}},
		{Name: "example", Clients: []string{"agent"}, IssuerHost: "login.example.com", TokenPath: "/oauth/token", APIHosts: nil},
	} {
		if _, err := New(File{Brokers: []Definition{definition}}, filepath.Join(t.TempDir(), "auth.json")); err == nil {
			t.Fatalf("unsafe definition accepted: %#v", definition)
		}
	}
}
