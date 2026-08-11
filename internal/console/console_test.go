package console

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abagile/veilgate/internal/flow"
)

func TestConsoleAuthenticationAndSanitizedAPI(t *testing.T) {
	store := flow.NewStore(10)
	stored, err := store.Add(context.Background(), flow.Flow{Client: "agent", Host: "api.openai.com", Decision: "allowed", Capture: flow.TrafficCapture{RequestBody: &flow.PayloadCapture{Text: "captured detail"}}})
	if err != nil {
		t.Fatal(err)
	}
	h, err := Handler(store, "operator", "secret-password")
	if err != nil {
		t.Fatal(err)
	}

	unauthorized := httptest.NewRecorder()
	h.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/flows", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}
	unauthorizedDetail := httptest.NewRecorder()
	h.ServeHTTP(unauthorizedDetail, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/flows/%d", stored.ID), nil))
	if unauthorizedDetail.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized detail status = %d", unauthorizedDetail.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/flows", nil)
	req.SetBasicAuth("operator", "secret-password")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var page flow.Page
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Flows) != 1 || page.Flows[0].Host != "api.openai.com" {
		t.Fatalf("flows = %#v", page.Flows)
	}
	if page.HasMore {
		t.Fatalf("has_more = %v", page.HasMore)
	}
	if strings.Contains(rec.Body.String(), "secret-password") || strings.Contains(rec.Body.String(), "captured detail") {
		t.Fatal("flow summary contains credentials or detailed capture")
	}

	detailReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/flows/%d", stored.ID), nil)
	detailReq.SetBasicAuth("operator", "secret-password")
	detailRec := httptest.NewRecorder()
	h.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK || !strings.Contains(detailRec.Body.String(), "captured detail") {
		t.Fatalf("detail response = %d %q", detailRec.Code, detailRec.Body.String())
	}
}

func TestConsoleDescribesInterceptionWithoutClaimingPayloadCapture(t *testing.T) {
	h, err := Handler(flow.NewStore(1), "", "")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	body := rec.Body.String()
	for _, want := range []string{"<th>Mode</th>", "id=\"traffic-workspace\"", "id=\"flow-panel\"", "id=\"flow-filters\"", "id=\"policy-trace\"", "id=\"capture-sections\"", "/static/formatters.js", "Credential-bearing header values appear as"} {
		if !strings.Contains(body, want) {
			t.Errorf("console body missing %q", want)
		}
	}
}

func TestFlowAPIFiltersAndRejectsInvalidDecision(t *testing.T) {
	store := flow.NewStore(10)
	for _, item := range []flow.Flow{
		{Client: "agent-a", Host: "api.example.com", Decision: "allowed"},
		{Client: "agent-b", Host: "other.example.com", Decision: "denied"},
	} {
		if _, err := store.Add(context.Background(), item); err != nil {
			t.Fatal(err)
		}
	}
	h, err := Handler(store, "", "")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/flows?client=agent-a&decision=allowed", nil))
	var page flow.Page
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || len(page.Flows) != 1 || page.Flows[0].Client != "agent-a" {
		t.Fatalf("filtered response = %d %#v", rec.Code, page.Flows)
	}

	invalid := httptest.NewRecorder()
	h.ServeHTTP(invalid, httptest.NewRequest(http.MethodGet, "/api/v1/flows?decision=maybe", nil))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid decision status = %d", invalid.Code)
	}

	badCursor := httptest.NewRecorder()
	h.ServeHTTP(badCursor, httptest.NewRequest(http.MethodGet, "/api/v1/flows?before_id=0", nil))
	if badCursor.Code != http.StatusBadRequest {
		t.Fatalf("invalid before_id status = %d", badCursor.Code)
	}
}

func TestHealthIsUnauthenticated(t *testing.T) {
	h, err := Handler(flow.NewStore(1), "operator", "secret-password")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
		t.Fatalf("health response = %d %q", rec.Code, rec.Body.String())
	}
}
