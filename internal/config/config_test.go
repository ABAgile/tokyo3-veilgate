package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsTrailingJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.json")
	data := `{"clients":[{"name":"agent","token":"012345678901234567890123","allowed_hosts":["example.com"]}]} {"unexpected":true}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load() accepted trailing JSON")
	}
}

func TestClientAllowsExactAndWildcardHosts(t *testing.T) {
	f := &File{Clients: []Client{{
		Name: "agent", Token: "012345678901234567890123",
		AllowedHosts: []string{"api.openai.com", "*.npmjs.org"},
		AllowedPorts: []int{443},
	}}}
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	client := &f.Clients[0]
	for _, tc := range []struct {
		host string
		port int
		want bool
	}{
		{"api.openai.com", 443, true},
		{"API.OPENAI.COM.", 443, true},
		{"registry.npmjs.org", 443, true},
		{"npmjs.org", 443, false},
		{"evilnpmjs.org", 443, false},
		{"api.openai.com", 80, false},
	} {
		if got := client.Allows(tc.host, tc.port); got != tc.want {
			t.Errorf("Allows(%q, %d) = %v, want %v", tc.host, tc.port, got, tc.want)
		}
	}
}

func TestClientUsesOpaqueTunnelForConfiguredHosts(t *testing.T) {
	f := &File{Clients: []Client{{
		Name:         "agent",
		Token:        "012345678901234567890123",
		AllowedHosts: []string{"*.npmjs.org", "*.github.com"},
		OpaqueHosts:  []string{"REGISTRY.NPMJS.ORG.", "*.GitHub.com"},
		AllowedPorts: []int{443},
	}}}
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	client := &f.Clients[0]
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"registry.npmjs.org", true},
		{"REGISTRY.NPMJS.ORG.", true},
		{"packages.github.com", true},
		{"github.com", false},
		{"evilgithub.com", false},
	} {
		if got := client.UsesOpaqueTunnel(tc.host); got != tc.want {
			t.Errorf("UsesOpaqueTunnel(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestClientAllowsAnyPublicHostOnAllowedPorts(t *testing.T) {
	f := &File{Clients: []Client{{
		Name: "any-host", Token: "012345678901234567890123",
		AllowAnyPublicHost: true,
	}}}
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	client := &f.Clients[0]
	if !f.HasAnyPublicHostClients() || !client.Allows("arbitrary.example", 443) {
		t.Fatal("any-public-host policy did not allow a valid hostname on the default port")
	}
	for _, target := range []struct {
		host string
		port int
	}{
		{"arbitrary.example", 80},
		{"127.0.0.1", 443},
		{"invalid_host", 443},
	} {
		if client.Allows(target.host, target.port) {
			t.Errorf("Allows(%q, %d) succeeded", target.host, target.port)
		}
	}
}

func TestAuthenticate(t *testing.T) {
	f := &File{Clients: []Client{{
		Name: "agent", Token: "012345678901234567890123",
		AllowedHosts: []string{"example.com"},
	}}}
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	if client, ok := f.Authenticate("012345678901234567890123"); !ok || client.Name != "agent" {
		t.Fatalf("Authenticate(valid) = %v, %v", client, ok)
	}
	if _, ok := f.Authenticate("wrong"); ok {
		t.Fatal("Authenticate(wrong) succeeded")
	}
}

// TestValidateRejectsSharedTokenNamesBothClients checks the operator gets
// enough to find the offending pair, and that the token itself is not echoed
// into an error that may be logged.
func TestValidateRejectsSharedTokenNamesBothClients(t *testing.T) {
	const shared = "012345678901234567890123"
	f := &File{Clients: []Client{
		{Name: "low", Token: shared, AllowedHosts: []string{"example.com"}},
		{Name: "high", Token: shared, AllowAnyPublicHost: true},
	}}
	err := f.Validate()
	if err == nil {
		t.Fatal("Validate() accepted a shared token")
	}
	message := err.Error()
	if !strings.Contains(message, "low") || !strings.Contains(message, "high") {
		t.Errorf("error does not name both clients: %q", message)
	}
	if strings.Contains(message, shared) {
		t.Errorf("error leaks the token: %q", message)
	}
}

// TestAuthenticateRefusesAmbiguousToken guards the authentication path
// directly. Validate is the primary defence, but File is constructible without
// it, and resolving an ambiguous credential last-match-wins would hand the
// caller whichever identity happened to be listed last.
func TestAuthenticateRefusesAmbiguousToken(t *testing.T) {
	const shared = "012345678901234567890123"
	unvalidated := &File{Clients: []Client{
		{Name: "low", Token: shared, AllowedHosts: []string{"example.com"}, AllowedPorts: []int{443}},
		{Name: "high", Token: shared, AllowAnyPublicHost: true, AllowedPorts: []int{443}},
	}}
	if client, ok := unvalidated.Authenticate(shared); ok {
		t.Fatalf("Authenticate(ambiguous) = %q, want refusal", client.Name)
	}
}

// TestAuthenticateAcceptsDistinctTokens confirms refusing ambiguity did not
// break the ordinary multi-client case.
func TestAuthenticateAcceptsDistinctTokens(t *testing.T) {
	f := &File{Clients: []Client{
		{Name: "first", Token: "aaaaaaaaaaaaaaaaaaaaaaaa", AllowedHosts: []string{"example.com"}},
		{Name: "second", Token: "bbbbbbbbbbbbbbbbbbbbbbbb", AllowedHosts: []string{"example.org"}},
		{Name: "third", Token: "cccccccccccccccccccccccccccc", AllowedHosts: []string{"example.net"}},
	}}
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ token, want string }{
		{"aaaaaaaaaaaaaaaaaaaaaaaa", "first"},
		{"bbbbbbbbbbbbbbbbbbbbbbbb", "second"},
		{"cccccccccccccccccccccccccccc", "third"},
	} {
		client, ok := f.Authenticate(tc.token)
		if !ok || client.Name != tc.want {
			t.Errorf("Authenticate(%q) = %v, %v, want %q", tc.token, client, ok, tc.want)
		}
	}
}

func TestValidateRejectsUnsafeConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name string
		file File
	}{
		{"empty", File{}},
		{"short token", File{Clients: []Client{{Name: "a", Token: "short", AllowedHosts: []string{"example.com"}}}}},
		{"no destination policy", File{Clients: []Client{{Name: "a", Token: "012345678901234567890123"}}}},
		{"middle wildcard", File{Clients: []Client{{Name: "a", Token: "012345678901234567890123", AllowedHosts: []string{"api.*.example.com"}}}}},
		{"opaque middle wildcard", File{Clients: []Client{{Name: "a", Token: "012345678901234567890123", AllowedHosts: []string{"example.com"}, OpaqueHosts: []string{"api.*.example.com"}}}}},
		{"unicode", File{Clients: []Client{{Name: "a", Token: "012345678901234567890123", AllowedHosts: []string{"éxample.com"}}}}},
		{"duplicate token", File{Clients: []Client{
			{Name: "low", Token: "012345678901234567890123", AllowedHosts: []string{"example.com"}},
			{Name: "high", Token: "012345678901234567890123", AllowAnyPublicHost: true},
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.file.Validate(); err == nil {
				t.Fatal("Validate() succeeded")
			}
		})
	}
}

func TestInterceptModeValidation(t *testing.T) {
	base := func(mode string, hosts ...string) File {
		return File{Clients: []Client{{
			Name: "a", Token: "012345678901234567890123", AllowedHosts: []string{"example.com"},
			InterceptMode: mode, InterceptHosts: hosts,
		}}}
	}
	for _, test := range []struct {
		name    string
		file    File
		wantErr bool
	}{
		{"default is intercept", base(""), false},
		{"explicit intercept", base(ModeIntercept), false},
		{"opaque with hosts", base(ModeOpaque, "API.Example.com."), false},
		{"inspect with hosts", base(ModeInspect, "api.example.com"), false},
		{"hosts in the default mode", base("", "api.example.com"), false},
		{"legacy all", base("all"), false},
		{"legacy listed", base("listed", "api.example.com"), false},
		{"unknown mode", base("some"), true},
		{"invalid pattern", base(ModeOpaque, "api.*.example.com"), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.file.Validate()
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}

	file := base(ModeOpaque, "API.Example.com.", "*.Models.example")
	if err := file.Validate(); err != nil {
		t.Fatal(err)
	}
	client := &file.Clients[0]
	if client.InterceptMode != ModeOpaque {
		t.Fatalf("mode = %q, want %q", client.InterceptMode, ModeOpaque)
	}
	for host, want := range map[string]bool{
		"api.example.com":  true,
		"API.EXAMPLE.COM.": true,
		"x.models.example": true,
		"models.example":   false,
		"other.example":    false,
	} {
		if got := client.InterceptsListedHost(host); got != want {
			t.Errorf("InterceptsListedHost(%q) = %v, want %v", host, got, want)
		}
	}
	def := base("")
	if err := def.Validate(); err != nil || def.Clients[0].InterceptMode != ModeIntercept {
		t.Fatalf("default mode = %q, want %q, err = %v", def.Clients[0].InterceptMode, ModeIntercept, err)
	}
	for legacy, want := range map[string]string{"all": ModeIntercept, "listed": ModeOpaque} {
		old := base(legacy)
		if err := old.Validate(); err != nil || old.Clients[0].InterceptMode != want {
			t.Fatalf("legacy mode %q = %q, want %q, err = %v", legacy, old.Clients[0].InterceptMode, want, err)
		}
	}
}

func TestDeprecatedObserveAllPublicHostsAliasesAllowAnyPublicHost(t *testing.T) {
	data := `{"clients":[{"name":"old","token":"012345678901234567890123","observe_all_public_hosts":true}]}`
	var f File
	if err := json.Unmarshal([]byte(data), &f); err != nil {
		t.Fatal(err)
	}
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	client := &f.Clients[0]
	if !client.AllowAnyPublicHost || client.ObserveAllPublicHosts || !client.Allows("arbitrary.example", 443) || !f.HasAnyPublicHostClients() {
		t.Fatalf("deprecated field was not folded into allow_any_public_host: %#v", client)
	}
	current := File{Clients: []Client{{Name: "new", Token: "012345678901234567890123", AllowAnyPublicHost: true}}}
	if err := current.Validate(); err != nil || !current.Clients[0].Allows("arbitrary.example", 443) {
		t.Fatalf("allow_any_public_host not honored: %v", err)
	}
}

func TestFileClientLooksUpByName(t *testing.T) {
	f := &File{Clients: []Client{
		{Name: "a", Token: "012345678901234567890123", AllowedHosts: []string{"example.com"}},
		{Name: "b", Token: "abcdefghijklmnopqrstuvwx", AllowedHosts: []string{"example.com"}},
	}}
	if client, ok := f.Client("b"); !ok || client != &f.Clients[1] {
		t.Fatalf("Client(b) = %v, %v", client, ok)
	}
	if _, ok := f.Client("missing"); ok {
		t.Fatal("unexpected client")
	}
}

func TestAllowedRulesValidationAndMatching(t *testing.T) {
	f := &File{Clients: []Client{{
		Name: "agent", Token: "012345678901234567890123", AllowedHosts: []string{"*.example.com"},
		InspectHosts: []string{"STORAGE.example.com."},
		AllowedRules: []Rule{
			{Host: "Storage.Example.com", Methods: []string{"get", "HEAD"}, PathPrefixes: []string{"/bucket", "/data/"}},
			{Host: "storage.example.com", Methods: []string{"PUT"}, PathPrefixes: []string{"/up/"}, MaxRequestBytes: 8},
		},
	}}}
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	client := &f.Clients[0]
	if !client.InspectsHost("storage.example.com") || client.InspectsHost("other.example.com") {
		t.Fatal("InspectsHost did not match the normalized pattern")
	}
	if !client.HasRulesFor("STORAGE.example.com.") || client.HasRulesFor("other.example.com") {
		t.Fatal("HasRulesFor did not scope rules to their host")
	}
	for _, test := range []struct {
		host, method, path string
		want               bool
		max                int64
	}{
		{"storage.example.com", "GET", "/bucket", true, 0},
		{"storage.example.com", "GET", "/bucket/obj", true, 0},
		{"storage.example.com", "HEAD", "/data/x", true, 0},
		{"storage.example.com", "GET", "/bucketeer", false, 0},
		{"storage.example.com", "GET", "/data", false, 0},
		{"storage.example.com", "POST", "/bucket/x", false, 0},
		{"storage.example.com", "PUT", "/up/x", true, 8},
		{"storage.example.com", "PUT", "/bucket/x", false, 0},
		{"other.example.com", "DELETE", "/anything", true, 0},
	} {
		rule, ok := client.MatchRule(test.host, test.method, test.path)
		if ok != test.want || (rule != nil && rule.MaxRequestBytes != test.max) {
			t.Errorf("MatchRule(%s %s %s) = %v, %v", test.host, test.method, test.path, rule, ok)
		}
	}
}

func TestAllowedRulesRejectInvalidEntries(t *testing.T) {
	for name, rule := range map[string]Rule{
		"empty rule":      {Host: "a.example.com"},
		"bad host":        {Host: "bad host", Methods: []string{"GET"}},
		"bad method":      {Host: "a.example.com", Methods: []string{"GE T"}},
		"connect":         {Host: "a.example.com", Methods: []string{"CONNECT"}},
		"relative prefix": {Host: "a.example.com", PathPrefixes: []string{"bucket/"}},
		"dot segment":     {Host: "a.example.com", PathPrefixes: []string{"/a/../b"}},
		"encoded prefix":  {Host: "a.example.com", PathPrefixes: []string{"/a%2fb"}},
		"empty segment":   {Host: "a.example.com", PathPrefixes: []string{"/a//b"}},
		"negative cap":    {Host: "a.example.com", Methods: []string{"PUT"}, MaxRequestBytes: -1},
	} {
		f := &File{Clients: []Client{{
			Name: "agent", Token: "012345678901234567890123", AllowedHosts: []string{"a.example.com"},
			AllowedRules: []Rule{rule},
		}}}
		if err := f.Validate(); err == nil {
			t.Errorf("%s: Validate() accepted the rule", name)
		}
	}
}

func TestAllowedRulesExpandMultipleHosts(t *testing.T) {
	f := &File{Clients: []Client{{
		Name: "agent", Token: "012345678901234567890123", AllowAnyPublicHost: true,
		AllowedRules: []Rule{
			{Hosts: []string{"A.example.com", "*.cdn.example.com", "a.example.com."}, Methods: []string{"get", "head"}},
			{Host: "b.example.com", Methods: []string{"PUT"}, MaxRequestBytes: 4},
		},
	}}}
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	client := &f.Clients[0]
	if len(client.AllowedRules) != 3 {
		t.Fatalf("expanded rules = %+v, want 3 (duplicate host removed)", client.AllowedRules)
	}
	for _, rule := range client.AllowedRules {
		if rule.Hosts != nil || rule.Host == "" {
			t.Fatalf("rule not expanded to a single host: %+v", rule)
		}
	}
	client.AllowedRules[0].Methods[0] = "POST"
	if client.AllowedRules[1].Methods[0] != "GET" {
		t.Fatal("expanded rules share a methods slice")
	}
	client.AllowedRules[0].Methods[0] = "GET"
	for _, test := range []struct {
		host, method string
		want         bool
	}{
		{"a.example.com", "GET", true},
		{"x.cdn.example.com", "HEAD", true},
		{"x.cdn.example.com", "PUT", false},
		{"b.example.com", "GET", false},
		{"b.example.com", "PUT", true},
	} {
		if _, ok := client.MatchRule(test.host, test.method, "/"); ok != test.want {
			t.Errorf("MatchRule(%s %s) = %v, want %v", test.host, test.method, ok, test.want)
		}
	}
	if err := f.Validate(); err != nil || len(client.AllowedRules) != 3 {
		t.Fatalf("second Validate() = %v, rules = %d; want idempotent", err, len(client.AllowedRules))
	}
}

func TestAllowedRulesRejectBadHostSelection(t *testing.T) {
	for name, rule := range map[string]Rule{
		"host and hosts": {Host: "a.example.com", Hosts: []string{"b.example.com"}, Methods: []string{"GET"}},
		"no host":        {Methods: []string{"GET"}},
		"bad hosts item": {Hosts: []string{"a.example.com", "bad host"}, Methods: []string{"GET"}},
	} {
		f := &File{Clients: []Client{{
			Name: "agent", Token: "012345678901234567890123", AllowAnyPublicHost: true,
			AllowedRules: []Rule{rule},
		}}}
		if err := f.Validate(); err == nil {
			t.Errorf("%s: Validate() accepted the rule", name)
		}
	}
}

func TestInterceptModeInspect(t *testing.T) {
	f := &File{Clients: []Client{{
		Name: "agent", Token: "012345678901234567890123", AllowedHosts: []string{"a.example.com"},
		InterceptMode: ModeInspect, InterceptHosts: []string{"A.example.com"},
	}}}
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	if f.Clients[0].InterceptHosts[0] != "a.example.com" {
		t.Fatalf("intercept_hosts = %v, want normalized", f.Clients[0].InterceptHosts)
	}
	bad := &File{Clients: []Client{{
		Name: "agent", Token: "012345678901234567890123", AllowedHosts: []string{"a.example.com"},
		InterceptMode: "everything",
	}}}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "inspect") {
		t.Fatalf("Validate() = %v, want an error naming the valid modes", err)
	}
}
