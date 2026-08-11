package hostpattern

import "testing"

func TestNormalizeAndMatches(t *testing.T) {
	pattern, err := Normalize(" *.Example.com. ")
	if err != nil || pattern != "*.example.com" {
		t.Fatalf("Normalize() = %q, %v", pattern, err)
	}
	for _, tc := range []struct {
		host string
		want bool
	}{
		{host: "api.example.com", want: true},
		{host: "example.com", want: false},
		{host: "evil-example.com", want: false},
	} {
		if got := Matches([]string{pattern}, tc.host); got != tc.want {
			t.Errorf("Matches(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestNormalizeRejectsUnsafeHostnames(t *testing.T) {
	for _, pattern := range []string{
		"api.*.example.com",
		"api_example.com",
		"éxample.com",
		"example..com",
	} {
		if _, err := Normalize(pattern); err == nil {
			t.Errorf("Normalize(%q) succeeded", pattern)
		}
	}
}
