package secret

import (
	"bytes"
	"fmt"
	"math/rand"
	"slices"
	"sort"
	"strings"
	"testing"
)

// This file holds a deliberately naive reference implementation of secret
// matching and checks the optimized trie matcher against it on generated
// inputs.
//
// The reference states the intended semantics directly: at each offset try
// every needle longest first, replace on the first hit, otherwise emit one byte
// and advance. It is obviously correct and obviously too slow, which is exactly
// what makes it useful as an oracle for the matcher that replaced it.

type referenceNeedle struct {
	name string
	from []byte
	to   []byte
}

func referenceReplace(data []byte, needles []referenceNeedle, masked []resolved) ([]byte, []string) {
	sort.SliceStable(needles, func(i, j int) bool { return len(needles[i].from) > len(needles[j].from) })
	var out bytes.Buffer
	out.Grow(len(data))
	used := make(map[string]struct{})
	for offset := 0; offset < len(data); {
		matched := false
		for _, needle := range needles {
			if len(needle.from) > 0 && bytes.HasPrefix(data[offset:], needle.from) {
				out.Write(needle.to)
				used[needle.name] = struct{}{}
				offset += len(needle.from)
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		for _, item := range masked {
			if length := maskedSecretLength(data[offset:], item.valueBytes); length > 0 {
				out.WriteString(item.Placeholder)
				used[item.Name] = struct{}{}
				offset += length
				matched = true
				break
			}
		}
		if !matched {
			out.WriteByte(data[offset])
			offset++
		}
	}
	return out.Bytes(), sortedNames(used)
}

func referenceScrub(b *Broker, data []byte, client, host string) ([]byte, []string) {
	if len(data) == 0 {
		return data, nil
	}
	needles := make([]referenceNeedle, 0, len(b.secrets)*4)
	masked := make([]resolved, 0, len(b.secrets))
	for _, item := range b.secrets {
		if slices.Contains(item.Clients, client) && matchesHost(item.AllowedHosts, host) {
			for _, representation := range item.representations {
				needles = append(needles, referenceNeedle{name: item.Name, from: representation, to: item.placeholderBytes})
			}
			masked = append(masked, item)
		}
	}
	return referenceReplace(data, needles, masked)
}

func referenceSanitize(b *Broker, data []byte) []byte {
	if len(data) == 0 {
		return append([]byte(nil), data...)
	}
	needles := make([]referenceNeedle, 0, len(b.secrets)*8)
	for _, item := range b.secrets {
		for _, representation := range item.representations {
			needles = append(needles, referenceNeedle{name: item.Name, from: representation, to: item.marker})
		}
		for _, representation := range item.placeholderRepresentations {
			needles = append(needles, referenceNeedle{name: item.Name, from: representation, to: item.marker})
		}
	}
	out, _ := referenceReplace(data, needles, nil)
	return out
}

// generatedBroker builds a policy whose values deliberately share leading runs
// and vary in length, so needles overlap and nest rather than being trivially
// distinguishable by their first byte.
func generatedBroker(t *testing.T, rng *rand.Rand, count int) *Broker {
	t.Helper()
	defs := make([]Definition, 0, count)
	env := make(map[string]string, count)
	alphabets := []string{"abcdef0123456789", "AB01-_", "sk", "xyz"}
	for i := range count {
		name := fmt.Sprintf("s%c%c", 'a'+rune(i/26), 'a'+rune(i%26))
		alphabet := alphabets[rng.Intn(len(alphabets))]
		var value strings.Builder
		if rng.Intn(2) == 0 {
			value.WriteString("sk-live-")
		}
		for target := 8 + rng.Intn(24); value.Len() < target; {
			value.WriteByte(alphabet[rng.Intn(len(alphabet))])
		}
		fmt.Fprintf(&value, "%03d", i) // New rejects duplicate values
		env["VEILGATED_"+strings.ToUpper(name)] = value.String()

		hosts := []string{"api.example.com"}
		if i%3 == 0 {
			hosts = []string{"*.example.org"}
		}
		clients := []string{"agent"}
		if i%2 == 0 {
			clients = []string{"agent", "other"}
		}
		defs = append(defs, Definition{Name: name, Placeholder: strings.ToUpper(name), Clients: clients, AllowedHosts: hosts})
	}
	broker, err := New(File{Secrets: defs}, func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		t.Fatalf("generated policy rejected: %v", err)
	}
	return broker
}

// generatedPayload splices real values, encoded representations, placeholders,
// masked renderings, and near-misses together so matches are dense and adjacent.
func generatedPayload(rng *rand.Rand, b *Broker, parts int) []byte {
	var out bytes.Buffer
	const noise = "the quick brown fox 0123456789 {}\"':,/=&?"
	for range parts {
		item := &b.secrets[rng.Intn(len(b.secrets))]
		switch rng.Intn(7) {
		case 0:
			out.Write(item.valueBytes)
		case 1:
			out.Write(item.representations[rng.Intn(len(item.representations))])
		case 2:
			out.Write(item.placeholderRepresentations[rng.Intn(len(item.placeholderRepresentations))])
		case 3:
			value := item.value
			if keep := 4 + rng.Intn(4); keep < len(value)-4 {
				out.WriteString(value[:keep])
				out.WriteString(strings.Repeat("*", 3+rng.Intn(6)))
				out.WriteString(value[len(value)-4:])
			}
		case 4: // a near miss that must not be replaced
			out.WriteString(item.value[:len(item.value)/2])
		default:
			for range 1 + rng.Intn(20) {
				out.WriteByte(noise[rng.Intn(len(noise))])
			}
		}
	}
	return out.Bytes()
}

func TestMatcherAgreesWithReferenceImplementation(t *testing.T) {
	rng := rand.New(rand.NewSource(20260809))
	scopes := []struct{ client, host string }{
		{"agent", "api.example.com"},
		{"other", "api.example.com"},
		{"agent", "sub.example.org"},
		{"agent", "unrelated.test"},
		{"nobody", "api.example.com"},
	}
	for iteration := range 400 {
		broker := generatedBroker(t, rng, 1+rng.Intn(12))
		payload := generatedPayload(rng, broker, 1+rng.Intn(40))

		if got, want := broker.Sanitize(payload), referenceSanitize(broker, payload); !bytes.Equal(got, want) {
			t.Fatalf("iteration %d: Sanitize() = %q, want %q\ninput: %q", iteration, got, want, payload)
		}
		for _, scope := range scopes {
			gotData, gotNames := broker.Scrub(payload, scope.client, scope.host)
			wantData, wantNames := referenceScrub(broker, payload, scope.client, scope.host)
			if !bytes.Equal(gotData, wantData) {
				t.Fatalf("iteration %d: Scrub(%s, %s) = %q, want %q\ninput: %q",
					iteration, scope.client, scope.host, gotData, wantData, payload)
			}
			if !slices.Equal(gotNames, wantNames) {
				t.Fatalf("iteration %d: Scrub(%s, %s) names = %v, want %v",
					iteration, scope.client, scope.host, gotNames, wantNames)
			}
		}
	}
}
