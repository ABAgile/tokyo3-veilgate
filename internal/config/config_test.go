package config

import (
	"os"
	"path/filepath"
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.file.Validate(); err == nil {
				t.Fatal("Validate() succeeded")
			}
		})
	}
}
