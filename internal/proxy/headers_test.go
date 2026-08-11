package proxy

import (
	"net/http"
	"testing"
)

func TestCaptureHeadersRetainsPartialHeader(t *testing.T) {
	header := http.Header{"X-Capture": {"first", "second"}}
	limit := int64(len("X-Capture") + len("first"))

	captures, truncated := captureHeaders(header, "", nil, limit)
	if !truncated {
		t.Fatal("captureHeaders did not report truncation")
	}
	if len(captures) != 1 || captures[0].Name != "X-Capture" {
		t.Fatalf("captures = %#v", captures)
	}
	if len(captures[0].Values) != 1 || captures[0].Values[0] != "first" {
		t.Fatalf("partial capture values = %#v", captures[0].Values)
	}
}
