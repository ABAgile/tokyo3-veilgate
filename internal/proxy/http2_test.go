package proxy

import "testing"

func TestInterceptedHTTP2MaxConcurrentStreams(t *testing.T) {
	for _, test := range []struct {
		name  string
		limit int64
		want  uint32
	}{
		{name: "default mediation limit", want: 32},
		{name: "small limit is capped", limit: 1, want: 64},
		{name: "four megabytes", limit: 4 << 20, want: 32},
		{name: "eight megabytes", limit: 8 << 20, want: 16},
		{name: "maximum configured limit", limit: 64 << 20, want: 2},
		{name: "oversized limit remains one", limit: 128 << 20, want: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := &Handler{MediationLimit: test.limit}
			if got := h.interceptedHTTP2MaxConcurrentStreams(); got != test.want {
				t.Fatalf("interceptedHTTP2MaxConcurrentStreams() = %d, want %d", got, test.want)
			}
		})
	}
}
