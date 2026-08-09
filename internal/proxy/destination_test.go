package proxy

import (
	"net/netip"
	"testing"
)

func TestIsPublic(t *testing.T) {
	for _, tc := range []struct {
		address string
		want    bool
	}{
		{"8.8.8.8", true},
		{"2606:4700:4700::1111", true},
		{"127.0.0.1", false},
		{"10.1.2.3", false},
		{"100.64.0.1", false},
		{"169.254.169.254", false},
		{"192.0.2.1", false},
		{"198.18.0.1", false},
		{"203.0.113.1", false},
		{"::1", false},
		{"fc00::1", false},
		{"fe80::1", false},
		{"::ffff:127.0.0.1", false},
	} {
		if got := isPublic(netip.MustParseAddr(tc.address)); got != tc.want {
			t.Errorf("isPublic(%s) = %v, want %v", tc.address, got, tc.want)
		}
	}
}
