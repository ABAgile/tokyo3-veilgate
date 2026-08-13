package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsLoopbackConsoleAddr(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want bool
	}{
		{name: "IPv4 loopback", addr: "127.0.0.1:8081", want: true},
		{name: "IPv6 loopback", addr: "[::1]:8081", want: true},
		{name: "mapped IPv4 loopback", addr: "[::ffff:127.0.0.1]:8081", want: true},
		{name: "localhost", addr: "localhost:8081", want: true},
		{name: "localhost subdomain", addr: "veilgate.localhost:8081", want: true},
		{name: "wildcard IPv4", addr: "0.0.0.0:8081", want: false},
		{name: "wildcard IPv6", addr: "[::]:8081", want: false},
		{name: "empty host", addr: ":8081", want: false},
		{name: "public IPv4", addr: "192.0.2.10:8081", want: false},
		{name: "hostname", addr: "console.example.com:8081", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isLoopbackConsoleAddr(test.addr); got != test.want {
				t.Fatalf("isLoopbackConsoleAddr(%q) = %v, want %v", test.addr, got, test.want)
			}
		})
	}
}

func TestValidateConsoleAuth(t *testing.T) {
	for _, test := range []struct {
		name        string
		addr        string
		username    string
		password    string
		wantErr     bool
		wantMessage string
	}{
		{name: "loopback may be unauthenticated", addr: "127.0.0.1:8081"},
		{name: "non-loopback requires credentials", addr: "0.0.0.0:8081", wantErr: true, wantMessage: "required"},
		{name: "hostname requires credentials", addr: "console.example.com:8081", wantErr: true},
		{name: "username without password", addr: "127.0.0.1:8081", username: "operator", wantErr: true},
		{name: "password without username", addr: "127.0.0.1:8081", password: "secret", wantErr: true},
		{name: "credentials secure non-loopback", addr: "0.0.0.0:8081", username: "operator", password: "secret"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateConsoleAuth(test.addr, test.username, test.password)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateConsoleAuth() error = %v, wantErr %v", err, test.wantErr)
			}
			if test.wantMessage != "" && (err == nil || !strings.Contains(err.Error(), test.wantMessage)) {
				t.Fatalf("error = %q, want message containing %q", err, test.wantMessage)
			}
		})
	}
}

func TestOptionalPolicyFileSkipsMissingAndEmptyPolicies(t *testing.T) {
	dir := t.TempDir()
	for _, test := range []struct {
		name       string
		data       string
		collection string
		wantEmpty  bool
	}{
		{name: "zero length", data: "", collection: "secrets", wantEmpty: true},
		{name: "whitespace", data: " \n\t", collection: "secrets", wantEmpty: true},
		{name: "empty object", data: `{}`, collection: "secrets", wantEmpty: true},
		{name: "empty secrets", data: `{"secrets":[]}`, collection: "secrets", wantEmpty: true},
		{name: "empty brokers", data: `{"brokers":null}`, collection: "brokers", wantEmpty: true},
		{name: "configured secrets", data: `{"secrets":[{}]}`, collection: "secrets"},
		{name: "malformed", data: `{`, collection: "secrets"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(dir, test.name+".json")
			if err := os.WriteFile(path, []byte(test.data), 0o600); err != nil {
				t.Fatal(err)
			}
			envName := "VEILGATED_SECRETS_FILE"
			if test.collection == "brokers" {
				envName = "VEILGATED_OAUTH_FILE"
			}
			t.Setenv(envName, "")
			got := optionalPolicyFile(envName, path, test.collection)
			if (got == "") != test.wantEmpty {
				t.Fatalf("optionalPolicyFile() = %q, wantEmpty %v", got, test.wantEmpty)
			}
		})
	}

	t.Setenv("VEILGATED_SECRETS_FILE", filepath.Join(dir, "missing.json"))
	if got := optionalPolicyFile("VEILGATED_SECRETS_FILE", filepath.Join(dir, "unused.json"), "secrets"); got != "" {
		t.Fatalf("missing policy path = %q, want empty", got)
	}
}

func TestRunServeValidatesConfigurationBeforeStarting(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "clients.json")
	if err := os.WriteFile(policyPath, []byte(`{"clients":[{"name":"agent","token":"012345678901234567890123","allowed_hosts":["example.com"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	variableNames := []string{
		"VEILGATED_FLOW_RETENTION", "VEILGATED_DIAL_TIMEOUT", "VEILGATED_SESSION_IDLE_TIMEOUT",
		"VEILGATED_SESSION_MAX_DURATION", "VEILGATED_UPSTREAM_RESPONSE_HEADER_TIMEOUT",
		"VEILGATED_CAPTURE_LIMIT_BYTES", "VEILGATED_MEDIATION_LIMIT_BYTES",
		"VEILGATED_RECORD_QUEUE_CAPACITY", "VEILGATED_RECORD_WORKERS",
		"VEILGATED_CONSOLE_ADDR", "VEILGATED_CONSOLE_USERNAME", "VEILGATED_CONSOLE_PASSWORD",
		"VEILGATED_PROXY_CERT", "VEILGATED_PROXY_KEY",
	}
	for _, test := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{name: "invalid retention", env: map[string]string{"VEILGATED_FLOW_RETENTION": "not-an-int"}, want: "VEILGATED_FLOW_RETENTION"},
		{name: "retention bounds", env: map[string]string{"VEILGATED_FLOW_RETENTION": "100001"}, want: "between 1 and 100000"},
		{name: "dial timeout bounds", env: map[string]string{"VEILGATED_DIAL_TIMEOUT": "500us"}, want: "at least 1ms"},
		{name: "idle timeout bounds", env: map[string]string{"VEILGATED_SESSION_IDLE_TIMEOUT": "500ms"}, want: "between 1s and 24h"},
		{name: "maximum duration follows idle timeout", env: map[string]string{"VEILGATED_SESSION_IDLE_TIMEOUT": "2s", "VEILGATED_SESSION_MAX_DURATION": "1s"}, want: "at least the idle timeout"},
		{name: "response header timeout bounds", env: map[string]string{"VEILGATED_UPSTREAM_RESPONSE_HEADER_TIMEOUT": "500ms"}, want: "between 1s and 10m"},
		{name: "capture bounds", env: map[string]string{"VEILGATED_CAPTURE_LIMIT_BYTES": "512"}, want: "between 1024 and 4194304"},
		{name: "mediation contains capture", env: map[string]string{"VEILGATED_CAPTURE_LIMIT_BYTES": "1024", "VEILGATED_MEDIATION_LIMIT_BYTES": "512"}, want: "at least the capture limit"},
		{name: "record queue capacity bounds", env: map[string]string{"VEILGATED_RECORD_QUEUE_CAPACITY": "-1"}, want: "at least 1"},
		{name: "record workers bounds", env: map[string]string{"VEILGATED_RECORD_WORKERS": "-1"}, want: "at least 1"},
		{name: "remote console credentials", env: map[string]string{"VEILGATED_CONSOLE_ADDR": "0.0.0.0:8081"}, want: "VEILGATED_CONSOLE_USERNAME and VEILGATED_CONSOLE_PASSWORD are required"},
		{name: "proxy certificate required", env: nil, want: "VEILGATED_PROXY_CERT"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("VEILGATED_CLIENTS_FILE", policyPath)
			for _, name := range variableNames {
				t.Setenv(name, "")
			}
			for name, value := range test.env {
				t.Setenv(name, value)
			}
			err := runServe(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("runServe() error = %v, want message containing %q", err, test.want)
			}
		})
	}
}
