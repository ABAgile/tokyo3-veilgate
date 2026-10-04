package proxy

import (
	"path/filepath"
	"testing"

	"github.com/abagile/veilgate/internal/config"
	"github.com/abagile/veilgate/internal/oauth"
)

func TestUsesOpaqueTunnelByInterceptMode(t *testing.T) {
	oauthBroker, err := oauth.New(oauth.File{Brokers: []oauth.Definition{{
		Name: "model", Clients: []string{"agent"}, IssuerHost: "login.model.example",
		TokenPath: "/oauth/token", APIHosts: []string{"api.model.example", "*.wild.example"},
	}}}, filepath.Join(t.TempDir(), "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	broker := CombineBrokers(proxyTestBroker(t), oauthBroker)
	if _, ok := broker.(brokerChain); !ok {
		t.Fatalf("broker = %T, want brokerChain", broker)
	}

	newClient := func(mode string, intercept, opaque []string) *config.Client {
		policy := &config.File{Clients: []config.Client{{
			Name: "agent", Token: "012345678901234567890123", ObserveAllPublicHosts: true,
			InterceptMode: mode, InterceptHosts: intercept, OpaqueHosts: opaque,
		}}}
		if err := policy.Validate(); err != nil {
			t.Fatal(err)
		}
		return &policy.Clients[0]
	}
	listed := newClient(config.InterceptListed, []string{"extra.example"}, []string{"cdn.wild.example"})
	all := newClient("", nil, []string{"registry.example"})

	for _, test := range []struct {
		name   string
		client *config.Client
		host   string
		want   bool
	}{
		{"listed: unlisted host is opaque", listed, "registry.npmjs.org", true},
		{"listed: static secret host is intercepted", listed, "allowed.example", false},
		{"listed: OAuth issuer is intercepted", listed, "login.model.example", false},
		{"listed: OAuth API host is intercepted", listed, "api.model.example", false},
		{"listed: OAuth wildcard API host is intercepted", listed, "x.wild.example", false},
		{"listed: explicit intercept host", listed, "extra.example", false},
		{"listed: opaque_hosts beats broker scope", listed, "cdn.wild.example", true},
		{"all: ordinary host is intercepted", all, "registry.npmjs.org", false},
		{"all: opaque_hosts is opaque", all, "registry.example", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := &Handler{Secrets: broker}
			if got := h.usesOpaqueTunnel(test.client, test.host); got != test.want {
				t.Fatalf("usesOpaqueTunnel(%q) = %v, want %v", test.host, got, test.want)
			}
		})
	}

	t.Run("listed without brokers", func(t *testing.T) {
		h := &Handler{}
		if !h.usesOpaqueTunnel(listed, "api.model.example") {
			t.Fatal("unlisted host must be opaque without a broker")
		}
		if h.usesOpaqueTunnel(listed, "extra.example") {
			t.Fatal("explicit intercept host must be intercepted")
		}
	})

	t.Run("broker scoped to another client", func(t *testing.T) {
		other := newClient(config.InterceptListed, nil, nil)
		other.Name = "other"
		h := &Handler{Secrets: broker}
		if !h.usesOpaqueTunnel(other, "api.model.example") {
			t.Fatal("broker scoped to agent must not intercept for other")
		}
	})
}
