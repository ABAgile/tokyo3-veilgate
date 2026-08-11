package secret

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const testPlaceholder = "VEILGATED_SECRET_0123456789abcdef"

func testBroker(t *testing.T) *Broker {
	t.Helper()
	broker, err := New(File{Secrets: []Definition{{
		Name: "api_key", ValueEnv: "REAL_API_KEY", Placeholder: testPlaceholder,
		Clients: []string{"agent"}, AllowedHosts: []string{"api.example.com"},
	}}}, func(name string) (string, bool) {
		if name == "VEILGATED_REAL_API_KEY" {
			return "real-host-secret", true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	return broker
}

func TestApplyReplacesAuthorizedHTTPSHeader(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	req.Header.Set("Authorization", "Bearer "+testPlaceholder)
	names, err := testBroker(t).Apply(req, "agent", "api.example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer real-host-secret" {
		t.Fatalf("Authorization = %q", got)
	}
	if len(names) != 1 || names[0] != "api_key" {
		t.Fatalf("names = %#v", names)
	}
}

func TestApplyReplacesBasicCredentials(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	encoded := base64.StdEncoding.EncodeToString([]byte("user:" + testPlaceholder))
	req.Header.Set("Authorization", "Basic "+encoded)
	if _, err := testBroker(t).Apply(req, "agent", "api.example.com", true); err != nil {
		t.Fatal(err)
	}
	_, encoded, _ = strings.Cut(req.Header.Get("Authorization"), " ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != "user:real-host-secret" {
		t.Fatalf("decoded credentials = %q", decoded)
	}
}

func TestApplyRejectsEmbeddedHeaderPlaceholders(t *testing.T) {
	broker := testBroker(t)
	for name, value := range map[string]string{
		"X-API-Key":     "prefix-" + testPlaceholder,
		"Authorization": "Bearer " + testPlaceholder + "-suffix",
	} {
		req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", nil)
		req.Header.Set(name, value)
		if _, err := broker.Apply(req, "agent", "api.example.com", true); err == nil {
			t.Fatalf("embedded placeholder accepted in %s", name)
		}
		if got := req.Header.Get(name); got != value {
			t.Fatalf("header %s mutated after rejection: %q", name, got)
		}
	}

	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	encoded := base64.StdEncoding.EncodeToString([]byte("user:" + testPlaceholder + "-suffix"))
	req.Header.Set("Authorization", "Basic "+encoded)
	if _, err := broker.Apply(req, "agent", "api.example.com", true); err == nil {
		t.Fatal("embedded Basic placeholder accepted")
	}
}

func TestApplyFailsClosedOutsideScope(t *testing.T) {
	for _, tc := range []struct {
		name   string
		client string
		host   string
		secure bool
	}{
		{"plaintext", "agent", "api.example.com", false},
		{"wrong client", "other", "api.example.com", true},
		{"wrong host", "agent", "other.example.com", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", nil)
			req.Header.Set("X-API-Key", testPlaceholder)
			if _, err := testBroker(t).Apply(req, tc.client, tc.host, tc.secure); err == nil {
				t.Fatal("Apply succeeded")
			}
			if got := req.Header.Get("X-API-Key"); got != testPlaceholder {
				t.Fatalf("denied request header = %q", got)
			}
		})
	}
}

func TestSubstituteQueryAndJSONBody(t *testing.T) {
	broker := testBroker(t)
	u, err := url.Parse("https://api.example.com/v1?key=" + url.QueryEscape(testPlaceholder) + "&model=test")
	if err != nil {
		t.Fatal(err)
	}
	names, err := broker.SubstituteQuery(u, "agent", "api.example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("key") != "real-host-secret" || len(names) != 1 || names[0] != "api_key" {
		t.Fatalf("query = %q names = %#v", u.RawQuery, names)
	}
	body, names, supported, err := broker.SubstituteBody("application/json", []byte(`{"token":"`+testPlaceholder+`","nested":["safe"]}`), "agent", "api.example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	if !supported || !strings.Contains(string(body), `"token":"real-host-secret"`) || len(names) != 1 {
		t.Fatalf("body = %s supported = %t names = %#v", body, supported, names)
	}
	if got := string(broker.Sanitize(body)); strings.Contains(got, "real-host-secret") || got != `{"nested":["safe"],"token":"[secret:api_key]"}` {
		t.Fatalf("sanitized body = %q", got)
	}
}

func TestSubstitutionRejectsEmbeddedAndPlaintextPlaceholders(t *testing.T) {
	broker := testBroker(t)
	for _, body := range []string{
		`{"token":"prefix-` + testPlaceholder + `"}`,
		`{"token":"` + testPlaceholder + `"}`,
	} {
		secure := strings.Contains(body, "prefix-")
		if _, _, _, err := broker.SubstituteBody("application/json", []byte(body), "agent", "api.example.com", secure); err == nil {
			t.Fatalf("SubstituteBody(%q, secure=%t) succeeded", body, secure)
		}
	}
}

func TestScrubReplacesScopedResponseSecret(t *testing.T) {
	broker := testBroker(t)
	scrubbed, names := broker.Scrub([]byte("result=real-host-secret"), "agent", "api.example.com")
	if got := string(scrubbed); got != "result="+testPlaceholder || len(names) != 1 || names[0] != "api_key" {
		t.Fatalf("scrubbed = %q names = %#v", got, names)
	}
	unchanged, names := broker.Scrub([]byte("real-host-secret"), "other", "api.example.com")
	if string(unchanged) != "real-host-secret" || len(names) != 0 {
		t.Fatalf("out-of-scope scrub = %q names = %#v", unchanged, names)
	}
}

func TestScrubRecognizesEncodedSecretReflection(t *testing.T) {
	broker := testBroker(t)
	scrubbed, names := broker.Scrub([]byte("rejected cmVhbC1ob3N0LXNlY3JldA=="), "agent", "api.example.com")
	if string(scrubbed) != "rejected "+testPlaceholder || len(names) != 1 {
		t.Fatalf("encoded scrub = %q names = %#v", scrubbed, names)
	}
}

func TestScrubRecognizesMaskedSecretReflection(t *testing.T) {
	broker := testBroker(t)
	scrubbed, names := broker.Scrub([]byte("rejected real-hos******cret"), "agent", "api.example.com")
	if string(scrubbed) != "rejected "+testPlaceholder || len(names) != 1 || names[0] != "api_key" {
		t.Fatalf("masked scrub = %q names = %#v", scrubbed, names)
	}
}

func TestScrubAndSanitizeDoNotRecursivelyRewritePlaceholders(t *testing.T) {
	broker, err := New(File{Secrets: []Definition{
		{Name: "first", ValueEnv: "FIRST", Placeholder: "aaaaaaaaaaaaaaaa", Clients: []string{"agent"}, AllowedHosts: []string{"api.example.com"}},
		{Name: "second", ValueEnv: "SECOND", Placeholder: "bbbbbbbbbbbbbbbb", Clients: []string{"agent"}, AllowedHosts: []string{"api.example.com"}},
	}}, func(name string) (string, bool) {
		return map[string]string{"VEILGATED_FIRST": "first-real-secret", "VEILGATED_SECOND": "VEILGATE"}[name], true
	})
	if err != nil {
		t.Fatal(err)
	}
	scrubbed, _ := broker.Scrub([]byte("first-real-secret"), "agent", "api.example.com")
	if string(scrubbed) != "VEILGATED_SECRET_aaaaaaaaaaaaaaaa" {
		t.Fatalf("recursive scrub = %q", scrubbed)
	}
	if got := string(broker.Sanitize(scrubbed)); got != "[secret:first]" {
		t.Fatalf("sanitized placeholder = %q", got)
	}
}

func TestNewAppliesPrefixesAndDefaultValueEnv(t *testing.T) {
	broker, err := New(File{Secrets: []Definition{{
		Name: "test_secret", Placeholder: "suffix_seed_12345678",
		Clients: []string{"agent"}, AllowedHosts: []string{"api.example.com"},
	}}}, func(name string) (string, bool) {
		if name == "VEILGATED_TEST_SECRET" {
			return "auto-prefixed-secret", true
		}
		return "", false
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	req.Header.Set("Authorization", "Bearer VEILGATED_SECRET_suffix_seed_12345678")
	names, err := broker.Apply(req, "agent", "api.example.com", true)
	if err != nil || len(names) != 1 || names[0] != "test_secret" || req.Header.Get("Authorization") != "Bearer auto-prefixed-secret" {
		t.Fatalf("Apply result = %#v, err = %v, auth = %q", names, err, req.Header.Get("Authorization"))
	}
}

func TestNewRejectsMissingHostValue(t *testing.T) {
	_, err := New(File{Secrets: []Definition{{
		Name: "api_key", ValueEnv: "MISSING", Placeholder: testPlaceholder,
		Clients: []string{"agent"}, AllowedHosts: []string{"api.example.com"},
	}}}, func(string) (string, bool) { return "", false })
	if err == nil {
		t.Fatal("New succeeded")
	}
}
