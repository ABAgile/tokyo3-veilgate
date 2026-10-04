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

func TestSubstitutionPreservesEmbeddedBodyPlaceholders(t *testing.T) {
	broker := testBroker(t)
	for _, tc := range []struct {
		contentType string
		body        string
	}{
		{"application/json", `{"prompt":"prefix-` + testPlaceholder + `-suffix"}`},
		{"application/x-www-form-urlencoded", "prompt=" + url.QueryEscape("prefix-"+testPlaceholder+"-suffix")},
	} {
		body, names, supported, err := broker.SubstituteBody(tc.contentType, []byte(tc.body), "agent", "api.example.com", true)
		if err != nil {
			t.Fatalf("SubstituteBody(%q) error = %v", tc.contentType, err)
		}
		if !supported || len(names) != 0 || string(body) != tc.body {
			t.Fatalf("SubstituteBody(%q) = %q, names = %#v, supported = %t", tc.contentType, body, names, supported)
		}
	}
}

func TestSubstitutionStillRejectsPlaintextBodyPlaceholders(t *testing.T) {
	body := []byte(`{"token":"` + testPlaceholder + `"}`)
	if _, _, _, err := testBroker(t).SubstituteBody("application/json", body, "agent", "api.example.com", false); err == nil {
		t.Fatal("SubstituteBody accepted a placeholder over plaintext HTTP")
	} else if !strings.Contains(err.Error(), "cannot be used over plaintext HTTP") {
		t.Fatalf("SubstituteBody error = %q", err)
	}
}

func TestSubstitutionStillRejectsEmbeddedQueryPlaceholders(t *testing.T) {
	u, err := url.Parse("https://api.example.com/v1?key=" + url.QueryEscape("prefix-"+testPlaceholder+"-suffix"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testBroker(t).SubstituteQuery(u, "agent", "api.example.com", true); err == nil {
		t.Fatal("SubstituteQuery accepted an embedded placeholder")
	} else if !strings.Contains(err.Error(), "complete value") {
		t.Fatalf("SubstituteQuery error = %q", err)
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

func TestScopesHost(t *testing.T) {
	broker := testBroker(t)
	for _, test := range []struct {
		client, host string
		want         bool
	}{
		{"agent", "api.example.com", true},
		{"agent", "API.EXAMPLE.COM.", true},
		{"agent", "other.example.com", false},
		{"other", "api.example.com", false},
	} {
		if got := broker.ScopesHost(test.client, test.host); got != test.want {
			t.Errorf("ScopesHost(%q, %q) = %v, want %v", test.client, test.host, got, test.want)
		}
	}
	var none *Broker
	if none.ScopesHost("agent", "api.example.com") {
		t.Fatal("nil broker must scope no host")
	}
}

func twoHostBroker(t *testing.T) *Broker {
	t.Helper()
	broker, err := New(File{Secrets: []Definition{
		{Name: "a_key", ValueEnv: "A", Placeholder: "aaaaaaaaaaaaaaaa", Clients: []string{"agent"}, AllowedHosts: []string{"a.example.com"}},
		{Name: "b_key", ValueEnv: "B", Placeholder: "bbbbbbbbbbbbbbbb", Clients: []string{"agent"}, AllowedHosts: []string{"b.example.com"}},
	}}, func(name string) (string, bool) {
		return map[string]string{"VEILGATED_A": "real-a-value", "VEILGATED_B": "real-b-value"}[name], true
	})
	if err != nil {
		t.Fatal(err)
	}
	return broker
}

const (
	placeholderA = "VEILGATED_SECRET_aaaaaaaaaaaaaaaa"
	placeholderB = "VEILGATED_SECRET_bbbbbbbbbbbbbbbb"
)

func TestSubstituteBodyTreatsOutOfScopePlaceholdersAsInert(t *testing.T) {
	broker := twoHostBroker(t)
	jsonBody := `{"a":"` + placeholderA + `","b":"` + placeholderB + `"}`
	for _, test := range []struct {
		name, contentType, body, host string
		want                          string
		wantNames                     []string
	}{
		{"scoped host substitutes only its own secret", "application/json", jsonBody, "a.example.com",
			`{"a":"real-a-value","b":"` + placeholderB + `"}`, []string{"a_key"}},
		{"host with no scope leaves JSON untouched", "application/json", jsonBody, "other.example.com", jsonBody, nil},
		{"host with no scope does not parse bodies", "application/json", "not json " + placeholderA, "other.example.com", "not json " + placeholderA, nil},
		{"host with no scope allows unsupported media", "application/octet-stream", "bin " + placeholderA, "other.example.com", "bin " + placeholderA, nil},
		{"out-of-scope form value is inert", "application/x-www-form-urlencoded", "k=" + placeholderB, "a.example.com", "k=" + placeholderB, nil},
		{"out-of-scope unsupported body is inert", "application/octet-stream", "bin " + placeholderB, "a.example.com", "bin " + placeholderB, nil},
		{"out-of-scope JSON key is inert", "application/json", `{"` + placeholderB + `":1}`, "a.example.com", `{"` + placeholderB + `":1}`, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, names, _, err := broker.SubstituteBody(test.contentType, []byte(test.body), "agent", test.host, true)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != test.want || strings.Join(names, ",") != strings.Join(test.wantNames, ",") {
				t.Fatalf("body = %q names = %v, want %q %v", got, names, test.want, test.wantNames)
			}
		})
	}
}

func TestSubstituteBodyStillFailsClosedInScope(t *testing.T) {
	broker := twoHostBroker(t)
	for _, test := range []struct {
		name, contentType, body, client string
		secure                          bool
	}{
		{"unsupported body", "application/octet-stream", "bin " + placeholderA, "agent", true},
		{"JSON key", "application/json", `{"` + placeholderA + `":1}`, "agent", true},
		{"form name", "application/x-www-form-urlencoded", placeholderA + "=1", "agent", true},
		{"malformed JSON", "application/json", "{" + placeholderA, "agent", true},
		{"plaintext HTTP", "application/json", `{"a":"` + placeholderA + `"}`, "agent", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, _, err := broker.SubstituteBody(test.contentType, []byte(test.body), test.client, "a.example.com", test.secure); err == nil {
				t.Fatal("expected failure")
			}
		})
	}
	// Another client has no scope on this host, so the same body is inert.
	if _, _, _, err := broker.SubstituteBody("application/octet-stream", []byte("bin "+placeholderA), "other", "a.example.com", true); err != nil {
		t.Fatalf("out-of-scope client: %v", err)
	}
}

func TestCredentialPositionsStillRejectOutOfScopePlaceholders(t *testing.T) {
	broker := twoHostBroker(t)
	req, _ := http.NewRequest(http.MethodGet, "https://b.example.com/", nil)
	req.Header.Set("Authorization", "Bearer "+placeholderA)
	if _, err := broker.Apply(req, "agent", "b.example.com", true); err == nil {
		t.Fatal("header placeholder outside scope must be rejected")
	}
	target, _ := url.Parse("https://b.example.com/?k=" + placeholderA)
	if _, err := broker.SubstituteQuery(target, "agent", "b.example.com", true); err == nil {
		t.Fatal("query placeholder outside scope must be rejected")
	}
}

func TestPlaceholderNamesForReportsOnlyScopedSecrets(t *testing.T) {
	broker := twoHostBroker(t)
	data := []byte(placeholderA + " " + placeholderB)
	for host, want := range map[string]string{"a.example.com": "a_key", "b.example.com": "b_key", "other.example.com": ""} {
		if got := strings.Join(broker.PlaceholderNamesFor(data, "agent", host), ","); got != want {
			t.Errorf("PlaceholderNamesFor(%q) = %q, want %q", host, got, want)
		}
	}
	if names := broker.PlaceholderNamesFor(data, "other", "a.example.com"); len(names) != 0 {
		t.Fatalf("other client names = %v", names)
	}
}
