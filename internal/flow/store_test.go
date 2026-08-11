package flow

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHostWildcardFilterMatching(t *testing.T) {
	ctx := context.Background()
	for name, newStore := range map[string]func() *Store{
		"memory": func() *Store { return NewStore(100) },
		"sqlite": func() *Store {
			s, err := Open("sqlite:"+filepath.Join(t.TempDir(), "wildcard.db"), 100)
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := newStore()
			defer store.Close()

			for _, host := range []string{
				"storage.googleapis.com",
				"dns.googleapis.com",
				"googleapis.com",
				"api.openai.com",
			} {
				if _, err := store.Add(ctx, Flow{Host: host, Client: "test"}); err != nil {
					t.Fatal(err)
				}
			}

			// Wildcard *.googleapis.com should match subdomains and root domain
			list, err := store.List(ctx, Filter{Host: "*.googleapis.com"})
			if err != nil {
				t.Fatal(err)
			}
			if len(list) != 3 {
				t.Fatalf("%s *.googleapis.com matched %d flows, want 3: %#v", name, len(list), list)
			}

			// Glob pattern *google*
			globList, err := store.List(ctx, Filter{Host: "*google*"})
			if err != nil {
				t.Fatal(err)
			}
			if len(globList) != 3 {
				t.Fatalf("%s *google* matched %d flows, want 3", name, len(globList))
			}

			// Exact match api.openai.com
			exactList, err := store.List(ctx, Filter{Host: "api.openai.com"})
			if err != nil {
				t.Fatal(err)
			}
			if len(exactList) != 1 || exactList[0].Host != "api.openai.com" {
				t.Fatalf("%s exact match failed: %#v", name, exactList)
			}
		})
	}
}

func TestMemoryStoreBoundsFiltersAndPublishesFlows(t *testing.T) {
	store := NewStore(2)
	ctx := context.Background()
	if empty, err := store.List(ctx, Filter{}); err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty List() = %#v, %v", empty, err)
	}
	events, cancel := store.Subscribe()
	defer cancel()
	first, err := store.Add(ctx, Flow{Host: "one.example", Client: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add(ctx, Flow{Host: "two.example", Client: "b"}); err != nil {
		t.Fatal(err)
	}
	third, err := store.Add(ctx, Flow{Host: "three.example", Client: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != 1 || third.ID != 3 {
		t.Fatalf("IDs = %d, %d", first.ID, third.ID)
	}
	list, err := store.List(ctx, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Host != "three.example" || list[1].Host != "two.example" {
		t.Fatalf("List() = %#v", list)
	}
	filtered, err := store.List(ctx, Filter{Client: "a"})
	if err != nil || len(filtered) != 1 || filtered[0].Host != "three.example" {
		t.Fatalf("filtered List() = %#v, %v", filtered, err)
	}
	select {
	case event := <-events:
		if event.ID != 1 {
			t.Fatalf("first event ID = %d", event.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("no subscriber event")
	}
	if got, ok, err := store.Get(ctx, 3); err != nil || !ok || got.Host != "three.example" {
		t.Fatalf("Get(3) = %#v, %v, %v", got, ok, err)
	}
	if _, ok, err := store.Get(ctx, 1); err != nil || ok {
		t.Fatalf("evicted Get(1) = %v, %v", ok, err)
	}
}

func TestListPagePaginatesAndCompletesSessionParents(t *testing.T) {
	ctx := context.Background()
	for _, newStore := range map[string]func() *Store{
		"memory": func() *Store { return NewStore(100) },
		"sqlite": func() *Store {
			s, err := Open("sqlite:"+filepath.Join(t.TempDir(), "page.db"), 100)
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
	} {
		store := newStore()
		// CONNECT parent (id 1) followed by three intercepted children (ids 2-4).
		if _, err := store.Add(ctx, Flow{SessionID: "s1", Method: "CONNECT", Host: "api.example", Mode: "intercepted-session"}); err != nil {
			t.Fatal(err)
		}
		for range 3 {
			if _, err := store.Add(ctx, Flow{SessionID: "s1", Method: "POST", Host: "api.example", Mode: "intercepted"}); err != nil {
				t.Fatal(err)
			}
		}
		first, err := store.ListPage(ctx, Filter{Limit: 3})
		if err != nil {
			t.Fatal(err)
		}
		if len(first.Flows) != 3 || !first.HasMore || first.NextBeforeID != 2 {
			t.Fatalf("first page = %#v", first)
		}
		// The parent (id 1) precedes this page but must be supplied for grouping.
		if len(first.SessionParents) != 1 || first.SessionParents[0].ID != 1 {
			t.Fatalf("session parents = %#v", first.SessionParents)
		}
		second, err := store.ListPage(ctx, Filter{Limit: 3, BeforeID: first.NextBeforeID})
		if err != nil {
			t.Fatal(err)
		}
		if len(second.Flows) != 1 || second.Flows[0].ID != 1 || second.NextBeforeID != 1 {
			t.Fatalf("second page = %#v", second)
		}
		// The parent is inside this page, so no separate completion is needed.
		if len(second.SessionParents) != 0 {
			t.Fatalf("unexpected parents = %#v", second.SessionParents)
		}
		if second.HasMore {
			t.Fatalf("second page HasMore = %v", second.HasMore)
		}
		_ = store.Close()
	}
}

func TestSQLiteIndexesSessionID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flows.db")
	store, err := Open("sqlite:"+path, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sqlite, ok := store.backend.(*sqliteStore)
	if !ok {
		t.Fatal("store is not backed by SQLite")
	}
	var definition string
	if err := sqlite.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'flows_session_idx'`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(definition, "session_id") {
		t.Fatalf("session index definition = %q", definition)
	}
}

func TestSQLiteDatabasePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flows.db")
	store, err := Open("sqlite:"+path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("new flow database mode = %04o, want 0600", got)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open("sqlite:"+path, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("reopened flow database mode = %04o, want 0600", got)
	}
}

func TestSQLiteMemoryUsesSingleConnection(t *testing.T) {
	ctx := context.Background()
	store, err := Open("sqlite::memory:", 100)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	sqlite, ok := store.backend.(*sqliteStore)
	if !ok {
		t.Fatal("store is not backed by SQLite")
	}
	if got := sqlite.db.Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("SQLite memory max open connections = %d, want 1", got)
	}

	const goroutines = 20
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*2)
	for range goroutines {
		wg.Go(func() {
			if _, err := store.Add(ctx, Flow{Host: "memory.example"}); err != nil {
				errCh <- err
			}
			if _, err := store.List(ctx, Filter{Limit: 100}); err != nil {
				errCh <- err
			}
		})
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("SQLite memory operation failed: %v", err)
	}
}

func TestSQLiteStorePersistsMetadataAndRetention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flows.db")
	ctx := context.Background()
	store, err := Open("sqlite:"+path, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []Flow{
		{StartedAt: time.Now(), Host: "one.example"},
		{StartedAt: time.Now(), Host: "two.example", SecretNames: []string{"api_key"}},
		{SessionID: "session-123", StartedAt: time.Now(), Host: "three.example", DownstreamProtocol: "h2", UpstreamProtocol: "http/1.1", ResponseSecretNames: []string{"api_key"}, PolicyTrace: []PolicyStep{{Check: "acl", Outcome: "pass"}}, Capture: TrafficCapture{Query: "key=[secret:api_key]", RequestHeaders: []HeaderCapture{{Name: "Content-Type", Values: []string{"application/json"}}}, ResponseHeaders: []HeaderCapture{{Name: "Set-Cookie", Values: []string{"[redacted]"}}}, RequestBody: &PayloadCapture{ContentType: "application/json", Text: `{"key":"[secret:api_key]"}`}, WebSocketMessages: []WebSocketMessage{{Direction: "client-to-upstream", Text: `{"event":"test"}`}}}},
	} {
		if _, err := store.Add(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open("sqlite:"+path, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	items, err := reopened.List(ctx, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Host != "three.example" || items[1].Host != "two.example" {
		t.Fatalf("persisted flows = %#v", items)
	}
	summary, err := reopened.ListPageSummary(ctx, Filter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Flows) != 2 || summary.Flows[0].Capture.Query != "" || summary.Flows[0].Capture.RequestBody != nil || summary.Flows[0].Capture.ResponseBody != nil || len(summary.Flows[0].Capture.RequestHeaders) != 0 {
		t.Fatalf("summary flows retained capture data = %#v", summary.Flows)
	}
	if items[0].SessionID != "session-123" || items[0].DownstreamProtocol != "h2" || items[0].UpstreamProtocol != "http/1.1" || len(items[0].PolicyTrace) != 1 || len(items[0].ResponseSecretNames) != 1 || items[0].Capture.Query != "key=[secret:api_key]" || len(items[0].Capture.RequestHeaders) != 1 || len(items[0].Capture.ResponseHeaders) != 1 || items[0].Capture.RequestBody == nil || len(items[0].Capture.WebSocketMessages) != 1 || len(items[1].SecretNames) != 1 {
		t.Fatalf("persisted metadata = %#v", items)
	}
}

func TestSQLiteRetentionIsAppliedOnInsertAndOpen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "retention.db")

	store, err := Open("sqlite:"+path, 100)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := store.Add(ctx, Flow{Host: "example.com"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open("sqlite:"+path, 2)
	if err != nil {
		t.Fatal(err)
	}
	count := sqliteFlowCount(t, reopened)
	if count != 2 {
		t.Fatalf("startup retention count = %d, want 2", count)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	insertStore, err := Open("sqlite:"+filepath.Join(t.TempDir(), "insert.db"), 2)
	if err != nil {
		t.Fatal(err)
	}
	defer insertStore.Close()
	for range 3 {
		if _, err := insertStore.Add(ctx, Flow{Host: "example.com"}); err != nil {
			t.Fatal(err)
		}
	}
	if count := sqliteFlowCount(t, insertStore); count != 3 {
		t.Fatalf("batched retention count = %d, want 3 before batch threshold", count)
	}
	if _, err := insertStore.Add(ctx, Flow{Host: "example.com"}); err != nil {
		t.Fatal(err)
	}
	if count := sqliteFlowCount(t, insertStore); count != 2 {
		t.Fatalf("batched retention count = %d, want 2 after batch purge", count)
	}
}

func sqliteFlowCount(t *testing.T, store *Store) int {
	t.Helper()
	sqlite, ok := store.backend.(*sqliteStore)
	if !ok {
		t.Fatal("store is not backed by SQLite")
	}
	var count int
	if err := sqlite.db.QueryRow("SELECT COUNT(*) FROM flows").Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestSQLiteConcurrentWritesNoBusyError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.db")
	ctx := context.Background()
	store, err := Open("sqlite:"+path, 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	const goroutines = 20
	const writesPerGoroutine = 25
	errCh := make(chan error, goroutines*writesPerGoroutine)
	done := make(chan struct{})

	for i := range goroutines {
		go func(g int) {
			for range writesPerGoroutine {
				_, err := store.Add(ctx, Flow{
					StartedAt: time.Now(),
					Client:    "test-client",
					Method:    "POST",
					Scheme:    "https",
					Host:      "concurrent.example",
					Port:      443,
					Path:      "/test",
					Mode:      "intercepted",
				})
				if err != nil {
					errCh <- err
				}
			}
			done <- struct{}{}
		}(i)
	}

	for range goroutines {
		<-done
	}
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent write failed: %v", err)
	}

	list, err := store.List(ctx, Filter{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != goroutines*writesPerGoroutine {
		t.Fatalf("stored flow count = %d, want %d", len(list), goroutines*writesPerGoroutine)
	}
}
