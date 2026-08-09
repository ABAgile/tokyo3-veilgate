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
		{"192.88.99.1", false},
	} {
		if got := isPublic(netip.MustParseAddr(tc.address)); got != tc.want {
			t.Errorf("isPublic(%s) = %v, want %v", tc.address, got, tc.want)
		}
	}
}

// TestIsPublicRejectsIPv6TransitionRanges covers the ranges that carry an
// embedded IPv4 destination. A relay or NAT64 gateway decapsulates them, so
// admitting one is equivalent to admitting the IPv4 address inside it.
func TestIsPublicRejectsIPv6TransitionRanges(t *testing.T) {
	for _, tc := range []struct {
		address string
		reason  string
	}{
		{"64:ff9b::7f00:1", "NAT64 well-known prefix embedding 127.0.0.1"},
		{"64:ff9b::a00:1", "NAT64 well-known prefix embedding 10.0.0.1"},
		{"64:ff9b::a9fe:a9fe", "NAT64 well-known prefix embedding 169.254.169.254"},
		{"64:ff9b:1::7f00:1", "NAT64 local-use prefix"},
		{"2002:7f00:1::", "6to4 embedding 127.0.0.1"},
		{"2002:a00:1::1", "6to4 embedding 10.0.0.1"},
		{"2001:0:1:2:3:4:5:6", "Teredo"},
		{"2001:10::1", "ORCHID"},
		{"2001:20::1", "ORCHIDv2"},
		{"192.88.99.1", "6to4 relay anycast"},
	} {
		if isPublic(netip.MustParseAddr(tc.address)) {
			t.Errorf("isPublic(%s) = true, want false (%s)", tc.address, tc.reason)
		}
	}
}

// TestIsPublicAcceptsNeighboursOfBlockedRanges pins the prefix boundaries so a
// future widening of the blocklist cannot quietly make real destinations
// unreachable.
func TestIsPublicAcceptsNeighboursOfBlockedRanges(t *testing.T) {
	for _, address := range []string{
		"2001:4860:4860::8888", // outside Teredo 2001::/32 and ORCHID /28s
		"2003::1",              // adjacent to 6to4 2002::/16
		"64:ff9c::1",           // adjacent to the NAT64 prefixes
		"192.88.98.1",          // adjacent to the 6to4 relay anycast block
		"192.89.0.1",
	} {
		if !isPublic(netip.MustParseAddr(address)) {
			t.Errorf("isPublic(%s) = false, want true", address)
		}
	}
}
