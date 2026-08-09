package config

import (
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

func TestClientObservesAnyValidHostOnAllowedPorts(t *testing.T) {
	f := &File{Clients: []Client{{
		Name: "observer", Token: "012345678901234567890123",
		ObserveAllPublicHosts: true,
	}}}
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	client := &f.Clients[0]
	if !f.HasObservationClients() || !client.Allows("arbitrary.example", 443) {
		t.Fatal("observation policy did not allow a valid hostname on the default port")
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
		{Name: "high", Token: shared, ObserveAllPublicHosts: true},
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
		{Name: "high", Token: shared, ObserveAllPublicHosts: true, AllowedPorts: []int{443}},
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
		{"unicode", File{Clients: []Client{{Name: "a", Token: "012345678901234567890123", AllowedHosts: []string{"éxample.com"}}}}},
		{"duplicate token", File{Clients: []Client{
			{Name: "low", Token: "012345678901234567890123", AllowedHosts: []string{"example.com"}},
			{Name: "high", Token: "012345678901234567890123", ObserveAllPublicHosts: true},
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.file.Validate(); err == nil {
				t.Fatal("Validate() succeeded")
			}
		})
	}
}
