package secret

import (
	"fmt"
	"strings"
	"testing"
)

// scopedBroker builds two secrets whose values overlap, so tests can pin how
// the shared trie resolves length and scope against each other.
func scopedBroker(t *testing.T, longHosts, shortHosts []string) *Broker {
	t.Helper()
	broker, err := New(File{Secrets: []Definition{
		{Name: "long_secret", ValueEnv: "LONG", Placeholder: "LONG", Clients: []string{"agent"}, AllowedHosts: longHosts},
		{Name: "short_secret", ValueEnv: "SHORT", Placeholder: "SHORT", Clients: []string{"agent"}, AllowedHosts: shortHosts},
	}}, func(name string) (string, bool) {
		switch name {
		case "VEILGATED_LONG":
			return "abcdefgh1234", true
		case "VEILGATED_SHORT":
			return "abcdefgh", true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	return broker
}

// TestScrubPrefersTheLongestOverlappingSecret pins longest-match-at-offset when
// one configured value is a prefix of another.
func TestScrubPrefersTheLongestOverlappingSecret(t *testing.T) {
	broker := scopedBroker(t, []string{"api.example.com"}, []string{"api.example.com"})
	out, names := broker.Scrub([]byte("x abcdefgh1234 y"), "agent", "api.example.com")
	if got, want := string(out), "x VEILGATED_SECRET_LONG y"; got != want {
		t.Errorf("Scrub() = %q, want %q", got, want)
	}
	if len(names) != 1 || names[0] != "long_secret" {
		t.Errorf("names = %v, want [long_secret]", names)
	}
}

// TestScrubFallsBackToShorterInScopeSecret is the case the shared trie makes
// possible to get wrong: the longest needle at an offset belongs to a secret
// that is out of scope for this host, so the shorter in-scope needle must still
// be found rather than the offset being skipped or the out-of-scope value
// replaced.
func TestScrubFallsBackToShorterInScopeSecret(t *testing.T) {
	broker := scopedBroker(t, []string{"elsewhere.example.com"}, []string{"api.example.com"})
	out, names := broker.Scrub([]byte("x abcdefgh1234 y"), "agent", "api.example.com")
	if got, want := string(out), "x VEILGATED_SECRET_SHORT1234 y"; got != want {
		t.Errorf("Scrub() = %q, want %q", got, want)
	}
	if len(names) != 1 || names[0] != "short_secret" {
		t.Errorf("names = %v, want [short_secret]", names)
	}
}

// TestScrubLeavesFullyOutOfScopeDataAlone confirms an out-of-scope needle is
// not replaced merely because it is present in the shared trie.
func TestScrubLeavesFullyOutOfScopeDataAlone(t *testing.T) {
	broker := scopedBroker(t, []string{"elsewhere.example.com"}, []string{"elsewhere.example.com"})
	out, names := broker.Scrub([]byte("x abcdefgh1234 y"), "agent", "api.example.com")
	if got, want := string(out), "x abcdefgh1234 y"; got != want {
		t.Errorf("Scrub() = %q, want %q", got, want)
	}
	if len(names) != 0 {
		t.Errorf("names = %v, want none", names)
	}
}

// TestSanitizeIgnoresScope checks sanitization still collapses every configured
// secret regardless of client or host, since it guards persisted and displayed
// data rather than one request.
func TestSanitizeIgnoresScope(t *testing.T) {
	broker := scopedBroker(t, []string{"elsewhere.example.com"}, []string{"elsewhere.example.com"})
	if got, want := string(broker.Sanitize([]byte("x abcdefgh1234 y"))), "x [secret:long_secret] y"; got != want {
		t.Errorf("Sanitize() = %q, want %q", got, want)
	}
}

func benchmarkBroker(b *testing.B, count int) *Broker {
	b.Helper()
	defs := make([]Definition, 0, count)
	env := make(map[string]string, count)
	for i := range count {
		name := fmt.Sprintf("secret_%c%c", 'a'+rune(i/26), 'a'+rune(i%26))
		defs = append(defs, Definition{
			Name: name, Placeholder: strings.ToUpper(name),
			Clients: []string{"agent"}, AllowedHosts: []string{"api.example.com"},
		})
		// A shared prefix is realistic for vendor-issued keys and is the shape
		// that defeats a first-byte-only prefilter.
		env["VEILGATED_"+strings.ToUpper(name)] = fmt.Sprintf("sk-live-%030d", i)
	}
	broker, err := New(File{Secrets: defs}, func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		b.Fatal(err)
	}
	return broker
}

// BenchmarkScrub guards against reintroducing a per-secret scan of the payload.
// Throughput must stay essentially flat as the secret count grows; if it falls
// off proportionally, matching has regressed to cost O(payload x secrets) and
// one large allowed response can again exhaust CPU.
func BenchmarkScrub(b *testing.B) {
	payload := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog 0123456789 ", 20000))
	for _, count := range []int{1, 10, 25, 100} {
		broker := benchmarkBroker(b, count)
		b.Run(fmt.Sprintf("secrets=%d", count), func(b *testing.B) {
			b.SetBytes(int64(len(payload)))
			for b.Loop() {
				broker.Scrub(payload, "agent", "api.example.com")
			}
		})
	}
}

// BenchmarkSanitize covers the other hot path, which runs over every capture,
// path, and reason and indexes twice as many needles per secret.
func BenchmarkSanitize(b *testing.B) {
	payload := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog 0123456789 ", 20000))
	for _, count := range []int{1, 25, 100} {
		broker := benchmarkBroker(b, count)
		b.Run(fmt.Sprintf("secrets=%d", count), func(b *testing.B) {
			b.SetBytes(int64(len(payload)))
			for b.Loop() {
				broker.Sanitize(payload)
			}
		})
	}
}
