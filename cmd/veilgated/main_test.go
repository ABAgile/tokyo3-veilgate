package main

import (
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
