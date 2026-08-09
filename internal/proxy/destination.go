package proxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// Resolver resolves a hostname to an approved public destination address.
type Resolver interface {
	Resolve(context.Context, string) (netip.Addr, error)
}

// PublicResolver rejects non-public and special-use destination addresses.
type PublicResolver struct {
	Resolver *net.Resolver
}

// Resolve returns the first public address. The selected address is later
// dialed directly, preventing a second DNS lookup from changing the decision.
func (r PublicResolver) Resolve(ctx context.Context, host string) (netip.Addr, error) {
	resolver := r.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addrs, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolve destination: %w", err)
	}
	for _, addr := range addrs {
		addr = addr.Unmap()
		if isPublic(addr) {
			return addr, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("destination has no permitted public address")
}

// prohibitedPrefixes lists every destination range that is not globally
// reachable, following the IANA IPv4 and IPv6 special-purpose address
// registries.
//
// The IPv6 transition ranges matter as much as the private ranges. Each of
// them embeds an IPv4 address that a gateway or relay decapsulates on the way
// out, so treating them as ordinary global unicast would let a hostile DNS
// answer such as 2002:7f00:1:: reach a blocked IPv4 destination without ever
// naming it.
var prohibitedPrefixes = mustPrefixes(
	// IPv4 special-purpose ranges.
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	// IPv6 special-purpose ranges.
	"::/128", "::1/128", "100::/64", "2001:db8::/32", "3fff::/20",
	"5f00::/16", "fc00::/7", "fe80::/10", "ff00::/8",
	// IPv6 transition and non-routable ranges that embed or stand in for an
	// IPv4 destination: NAT64 (well-known and local-use), Teredo, 6to4, and
	// ORCHID.
	"64:ff9b::/96", "64:ff9b:1::/48", "2001::/32", "2002::/16",
	"2001:10::/28", "2001:20::/28",
)

func mustPrefixes(raw ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(raw))
	for _, value := range raw {
		out = append(out, netip.MustParsePrefix(value))
	}
	return out
}

func isPublic(addr netip.Addr) bool {
	if !addr.IsValid() || !addr.IsGlobalUnicast() {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range prohibitedPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func dialAddress(addr netip.Addr, port int) string {
	return net.JoinHostPort(addr.String(), strconv.Itoa(port))
}

func defaultDialer(timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	return d.DialContext
}
