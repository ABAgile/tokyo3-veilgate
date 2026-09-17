// Package flow stores sanitized proxy transactions and bounded traffic captures.
package flow

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// PolicyStep is one ordered, sanitized policy decision.
type PolicyStep struct {
	Check   string `json:"check"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

// PayloadCapture is one bounded textual HTTP payload. Omitted identifies a
// binary or unsupported media type whose content was deliberately not stored;
// Truncated identifies a supported payload whose retained text hit the capture
// limit.
type PayloadCapture struct {
	ContentType string `json:"content_type,omitempty"`
	Text        string `json:"text,omitempty"`
	Omitted     bool   `json:"omitted,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

// HeaderCapture is one sanitized HTTP header with all retained values.
type HeaderCapture struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

// WebSocketMessage is one bounded sanitized text capture or metadata-only
// binary message record. Binary bytes are never persisted.
type WebSocketMessage struct {
	Direction string `json:"direction"`
	Kind      string `json:"kind,omitempty"`
	Text      string `json:"text,omitempty"`
	Size      int64  `json:"size,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
}

// TrafficCapture contains bounded application data after secret sanitization.
type TrafficCapture struct {
	Query             string             `json:"query,omitempty"`
	RequestHeaders    []HeaderCapture    `json:"request_headers,omitempty"`
	ResponseHeaders   []HeaderCapture    `json:"response_headers,omitempty"`
	RequestBody       *PayloadCapture    `json:"request_body,omitempty"`
	ResponseBody      *PayloadCapture    `json:"response_body,omitempty"`
	WebSocketMessages []WebSocketMessage `json:"websocket_messages,omitempty"`
	Truncated         bool               `json:"truncated,omitempty"`
}

// Flow is the sanitized record of one proxy request or tunnel.
type Flow struct {
	ID                   uint64         `json:"id"`
	SessionID            string         `json:"session_id,omitempty"`
	StartedAt            time.Time      `json:"started_at"`
	Duration             time.Duration  `json:"duration_ns"`
	Client               string         `json:"client,omitempty"`
	Method               string         `json:"method"`
	Scheme               string         `json:"scheme"`
	Host                 string         `json:"host"`
	Port                 int            `json:"port"`
	Path                 string         `json:"path,omitempty"`
	Mode                 string         `json:"mode"`
	DownstreamProtocol   string         `json:"downstream_protocol,omitempty"`
	UpstreamProtocol     string         `json:"upstream_protocol,omitempty"`
	DestinationIP        string         `json:"destination_ip,omitempty"`
	Decision             string         `json:"decision"`
	Reason               string         `json:"reason,omitempty"`
	Status               int            `json:"status,omitempty"`
	BytesSent            int64          `json:"bytes_sent"`
	BytesReceived        int64          `json:"bytes_received"`
	BytesReceivedDecoded int64          `json:"bytes_received_decoded"` // decompressed response-body bytes
	SecretNames          []string       `json:"secret_names,omitempty"`
	ResponseSecretNames  []string       `json:"response_secret_names,omitempty"`
	PolicyTrace          []PolicyStep   `json:"policy_trace,omitempty"`
	Capture              TrafficCapture `json:"capture"`
}

// Trace appends a policy step without recording credentials or unsanitized data.
func (f *Flow) Trace(check, outcome, detail string) {
	f.PolicyTrace = append(f.PolicyTrace, PolicyStep{Check: check, Outcome: outcome, Detail: detail})
}

// Filter limits flow list results. String fields are exact matches.
type Filter struct {
	Client   string
	Host     string
	Decision string
	Mode     string
	Method   string
	Sessions []string
	BeforeID uint64
	Limit    int
}

// Page is one newest-first slice of flows plus the keyset cursor needed to
// request the next older page. SessionParents carries CONNECT rows fetched to
// complete groups whose parent falls before the page; they are not part of the
// cursor sequence.
type Page struct {
	Flows          []Flow `json:"flows"`
	SessionParents []Flow `json:"session_parents,omitempty"`
	NextBeforeID   uint64 `json:"next_before_id,omitempty"`
	HasMore        bool   `json:"has_more"`
}

// Matches reports whether item satisfies the exact-match filter.
func (f Filter) Matches(item Flow) bool { return matchesFilter(item, f) }

type backend interface {
	Add(context.Context, Flow, int) (Flow, error)
	List(context.Context, Filter, int) ([]Flow, error)
	ListSummary(context.Context, Filter, int) ([]Flow, error)
	Get(context.Context, uint64) (Flow, bool, error)
	Close() error
}

// Store coordinates a persistent or in-memory backend with live subscribers.
type Store struct {
	backend  backend
	capacity int

	mu          sync.Mutex
	subscribers map[chan Flow]struct{}
}

// Open selects an in-memory store for an empty URL or a SQLite store for
// sqlite:<path>. SQLite schema migration happens before Open returns.
func Open(databaseURL string, capacity int) (*Store, error) {
	if capacity < 1 {
		return nil, errors.New("flow retention capacity must be positive")
	}
	var b backend
	if databaseURL == "" {
		b = &memoryBackend{}
	} else {
		path, ok := strings.CutPrefix(databaseURL, "sqlite:")
		if !ok || path == "" {
			return nil, errors.New("VEILGATED_DATABASE_URL must be empty or sqlite:<path>")
		}
		sqliteBackend, err := openSQLite(path, capacity)
		if err != nil {
			return nil, err
		}
		b = sqliteBackend
	}
	return &Store{backend: b, capacity: capacity, subscribers: make(map[chan Flow]struct{})}, nil
}

// NewStore constructs the in-memory variant for tests and embedded use.
func NewStore(capacity int) *Store {
	store, err := Open("", capacity)
	if err != nil {
		panic(err)
	}
	return store
}

// Add persists a flow, applies retention, and notifies live subscribers.
func (s *Store) Add(ctx context.Context, item Flow) (Flow, error) {
	item, err := s.backend.Add(ctx, item, s.capacity)
	if err != nil {
		return Flow{}, err
	}
	s.mu.Lock()
	for ch := range s.subscribers {
		select {
		case ch <- item:
		default:
		}
	}
	s.mu.Unlock()
	return item, nil
}

// List returns newest-first flows matching filter.
func (s *Store) List(ctx context.Context, filter Filter) ([]Flow, error) {
	if filter.Limit <= 0 || filter.Limit > s.capacity {
		filter.Limit = s.capacity
	}
	return s.backend.List(ctx, filter, s.capacity)
}

// ListPage returns a bounded newest-first page for filter, a keyset cursor for
// the next older page, and any CONNECT parents needed to render groups whose
// parent precedes the page. filter.BeforeID, when non-zero, restricts results
// to flows older than that id.
func (s *Store) ListPage(ctx context.Context, filter Filter) (Page, error) {
	return s.listPage(ctx, filter, false)
}

// ListPageSummary returns the same page shape without capture data. It is used
// by list views that fetch full flow details separately.
func (s *Store) ListPageSummary(ctx context.Context, filter Filter) (Page, error) {
	return s.listPage(ctx, filter, true)
}

func (s *Store) listPage(ctx context.Context, filter Filter, summary bool) (Page, error) {
	if filter.Limit <= 0 || filter.Limit > s.capacity {
		filter.Limit = s.capacity
	}
	list := s.backend.List
	if summary {
		list = s.backend.ListSummary
	}
	items, err := list(ctx, filter, s.capacity)
	if err != nil {
		return Page{}, err
	}
	page := Page{Flows: items, HasMore: len(items) == filter.Limit}
	if len(items) == 0 {
		return page, nil
	}
	minID := items[0].ID
	present := make(map[string]bool)
	missing := make([]string, 0)
	seen := make(map[string]bool)
	for _, item := range items {
		if item.ID < minID {
			minID = item.ID
		}
		if item.Method == http.MethodConnect && item.SessionID != "" {
			present[item.SessionID] = true
		}
	}
	page.NextBeforeID = minID
	for _, item := range items {
		if item.SessionID == "" || present[item.SessionID] || seen[item.SessionID] {
			continue
		}
		seen[item.SessionID] = true
		missing = append(missing, item.SessionID)
	}
	if len(missing) > 0 {
		parentFilter := filter
		parentFilter.Mode = ""
		parentFilter.Method = http.MethodConnect
		parentFilter.Sessions = missing
		parentFilter.BeforeID = minID
		parentFilter.Limit = len(missing)
		parents, err := list(ctx, parentFilter, s.capacity)
		if err != nil {
			return Page{}, err
		}
		page.SessionParents = parents
	}
	return page, nil
}

// Get retrieves one retained flow.
func (s *Store) Get(ctx context.Context, id uint64) (Flow, bool, error) {
	return s.backend.Get(ctx, id)
}

// Subscribe returns a best-effort live stream and idempotent cancellation.
func (s *Store) Subscribe() (<-chan Flow, func()) {
	ch := make(chan Flow, 16)
	s.mu.Lock()
	s.subscribers[ch] = struct{}{}
	s.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			s.mu.Lock()
			delete(s.subscribers, ch)
			close(ch)
			s.mu.Unlock()
		})
	}
}

// Close releases the selected backend.
func (s *Store) Close() error { return s.backend.Close() }

type memoryBackend struct {
	mu     sync.RWMutex
	nextID uint64
	start  int
	count  int
	flows  []Flow
}

func (b *memoryBackend) Add(_ context.Context, item Flow, capacity int) (Flow, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.flows) == 0 {
		b.flows = make([]Flow, capacity)
	}
	b.nextID++
	item.ID = b.nextID
	index := (b.start + b.count) % len(b.flows)
	if b.count == len(b.flows) {
		b.flows[b.start] = item
		b.start = (b.start + 1) % len(b.flows)
	} else {
		b.flows[index] = item
		b.count++
	}
	return item, nil
}

func (b *memoryBackend) List(_ context.Context, filter Filter, _ int) ([]Flow, error) {
	return b.list(filter, false)
}

func (b *memoryBackend) ListSummary(_ context.Context, filter Filter, _ int) ([]Flow, error) {
	return b.list(filter, true)
}

func (b *memoryBackend) list(filter Filter, summary bool) ([]Flow, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]Flow, 0, min(filter.Limit, b.count))
	for offset := 0; offset < b.count && len(out) < filter.Limit; offset++ {
		index := (b.start + b.count - 1 - offset) % len(b.flows)
		item := b.flows[index]
		if !matchesFilter(item, filter) {
			continue
		}
		if summary {
			out = append(out, cloneFlowSummary(item))
		} else {
			out = append(out, cloneFlow(item))
		}
	}
	return out, nil
}

func sessionMatch(item Flow, sessions []string) bool {
	return len(sessions) == 0 || slices.Contains(sessions, item.SessionID)
}

func (b *memoryBackend) Get(_ context.Context, id uint64) (Flow, bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for offset := 0; offset < b.count; offset++ {
		index := (b.start + offset) % len(b.flows)
		item := b.flows[index]
		if item.ID == id {
			return cloneFlow(item), true, nil
		}
	}
	return Flow{}, false, nil
}

func (*memoryBackend) Close() error { return nil }

func cloneFlow(item Flow) Flow {
	item.SecretNames = append([]string(nil), item.SecretNames...)
	item.ResponseSecretNames = append([]string(nil), item.ResponseSecretNames...)
	item.PolicyTrace = append([]PolicyStep(nil), item.PolicyTrace...)
	item.Capture.RequestHeaders = cloneHeaders(item.Capture.RequestHeaders)
	item.Capture.ResponseHeaders = cloneHeaders(item.Capture.ResponseHeaders)
	item.Capture.WebSocketMessages = append([]WebSocketMessage(nil), item.Capture.WebSocketMessages...)
	if item.Capture.RequestBody != nil {
		copy := *item.Capture.RequestBody
		item.Capture.RequestBody = &copy
	}
	if item.Capture.ResponseBody != nil {
		copy := *item.Capture.ResponseBody
		item.Capture.ResponseBody = &copy
	}
	return item
}

func cloneFlowSummary(item Flow) Flow {
	item.SecretNames = nil
	item.ResponseSecretNames = nil
	item.PolicyTrace = nil
	item.Capture = TrafficCapture{}
	return item
}

func cloneHeaders(headers []HeaderCapture) []HeaderCapture {
	cloned := make([]HeaderCapture, len(headers))
	for i, header := range headers {
		cloned[i] = HeaderCapture{Name: header.Name, Values: append([]string(nil), header.Values...)}
	}
	return cloned
}

func matchesFilter(item Flow, filter Filter) bool {
	return (filter.Client == "" || item.Client == filter.Client) &&
		(filter.Host == "" || matchHostPattern(filter.Host, item.Host)) &&
		(filter.Decision == "" || item.Decision == filter.Decision) &&
		(filter.Mode == "" || item.Mode == filter.Mode) &&
		(filter.Method == "" || item.Method == filter.Method) &&
		(filter.BeforeID == 0 || item.ID < filter.BeforeID) &&
		sessionMatch(item, filter.Sessions)
}

func matchHostPattern(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = strings.ToLower(strings.TrimSpace(host))
	if pattern == "" || pattern == host {
		return true
	}
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	if strings.ContainsAny(pattern, "*?") {
		if matched, err := filepath.Match(pattern, host); err == nil && matched {
			return true
		}
	}
	return false
}

type sqliteStore struct {
	db       *sql.DB
	writeMu  sync.Mutex
	retained int
}

const (
	retentionBatch  = 100
	trimFlowsSQL    = `DELETE FROM flows WHERE id <= (SELECT id FROM flows ORDER BY id DESC LIMIT 1 OFFSET ?)`
	deleteOldestSQL = `DELETE FROM flows WHERE id IN (SELECT id FROM flows ORDER BY id ASC LIMIT ?)`
)

func openSQLite(path string, capacity int) (*sqliteStore, error) {
	persistent, err := prepareSQLiteFile(path)
	if err != nil {
		return nil, err
	}
	dsn := path
	if !strings.HasPrefix(dsn, "file:") {
		dsn = "file:" + dsn
	}
	if strings.Contains(dsn, "?") {
		dsn += "&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate"
	} else {
		dsn += "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open flow database: %w", err)
	}
	if !persistent {
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
	}
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS flows (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			started_at_ns INTEGER NOT NULL,
			duration_ns INTEGER NOT NULL,
			client TEXT NOT NULL,
			method TEXT NOT NULL,
			scheme TEXT NOT NULL,
			host TEXT NOT NULL,
			port INTEGER NOT NULL,
			path TEXT NOT NULL,
			mode TEXT NOT NULL,
			destination_ip TEXT NOT NULL,
			decision TEXT NOT NULL,
			reason TEXT NOT NULL,
			status INTEGER NOT NULL,
			bytes_sent INTEGER NOT NULL,
			bytes_received INTEGER NOT NULL,
			bytes_received_decoded INTEGER NOT NULL,
			secret_names TEXT NOT NULL,
			policy_trace TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS flows_started_idx ON flows(started_at_ns DESC)`,
		`CREATE INDEX IF NOT EXISTS flows_client_idx ON flows(client, id DESC)`,
		`CREATE INDEX IF NOT EXISTS flows_host_idx ON flows(host, id DESC)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("initialize flow database: %w", err)
		}
	}
	for _, migration := range []struct {
		column     string
		definition string
	}{
		{"response_secret_names", `TEXT NOT NULL DEFAULT 'null'`},
		{"capture", `TEXT NOT NULL DEFAULT '{}'`},
		{"session_id", `TEXT NOT NULL DEFAULT ''`},
		{"downstream_protocol", `TEXT NOT NULL DEFAULT ''`},
		{"upstream_protocol", `TEXT NOT NULL DEFAULT ''`},
		{"bytes_received_decoded", `INTEGER NOT NULL DEFAULT 0`},
	} {
		exists, err := sqliteColumnExists(db, "flows", migration.column)
		if err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("inspect flow database schema: %w", err)
		}
		if !exists {
			if _, err := db.Exec(`ALTER TABLE flows ADD COLUMN ` + migration.column + ` ` + migration.definition); err != nil {
				_ = db.Close()
				return nil, fmt.Errorf("migrate flow database: %w", err)
			}
		}
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS flows_session_idx ON flows(session_id, id DESC)`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize flow session index: %w", err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 5`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set flow database version: %w", err)
	}
	if err := trimSQLite(db, capacity); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apply flow retention: %w", err)
	}
	var retained int
	if err := db.QueryRow(`SELECT COUNT(*) FROM flows`).Scan(&retained); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("count retained flows: %w", err)
	}
	return &sqliteStore{db: db, retained: retained}, nil
}

func trimSQLite(db *sql.DB, capacity int) error {
	_, err := db.Exec(trimFlowsSQL, capacity)
	return err
}

func prepareSQLiteFile(path string) (bool, error) {
	filesystemPath, persistent, err := sqliteFilesystemPath(path)
	if err != nil {
		return false, err
	}
	if !persistent {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(filesystemPath), 0o750); err != nil {
		return false, fmt.Errorf("create flow database directory: %w", err)
	}
	if info, err := os.Lstat(filesystemPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return false, errors.New("flow database must not be a symbolic link")
		}
		if !info.Mode().IsRegular() {
			return false, errors.New("flow database must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect flow database: %w", err)
	}
	file, err := os.OpenFile(filesystemPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return false, fmt.Errorf("create flow database: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return false, fmt.Errorf("secure flow database: %w", err)
	}
	if err := file.Close(); err != nil {
		return false, fmt.Errorf("close flow database: %w", err)
	}
	return true, nil
}

func sqliteFilesystemPath(path string) (string, bool, error) {
	if path == ":memory:" || strings.HasPrefix(path, "file::memory:") {
		return "", false, nil
	}
	if !strings.HasPrefix(path, "file:") {
		return path, true, nil
	}
	parsed, err := url.Parse(path)
	if err != nil {
		return "", false, fmt.Errorf("parse flow database URI: %w", err)
	}
	if parsed.Host != "" && parsed.Host != "localhost" {
		return "", false, errors.New("flow database URI must use a local path")
	}
	if strings.EqualFold(parsed.Query().Get("mode"), "memory") {
		return "", false, nil
	}
	if parsed.Path == "" {
		return "", false, errors.New("flow database URI requires a path")
	}
	return parsed.Path, true, nil
}

func sqliteColumnExists(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (s *sqliteStore) Add(ctx context.Context, item Flow, capacity int) (Flow, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	secretNames, err := json.Marshal(item.SecretNames)
	if err != nil {
		return Flow{}, fmt.Errorf("encode secret names: %w", err)
	}
	responseSecretNames, err := json.Marshal(item.ResponseSecretNames)
	if err != nil {
		return Flow{}, fmt.Errorf("encode response secret names: %w", err)
	}
	policyTrace, err := json.Marshal(item.PolicyTrace)
	if err != nil {
		return Flow{}, fmt.Errorf("encode policy trace: %w", err)
	}
	capture, err := json.Marshal(item.Capture)
	if err != nil {
		return Flow{}, fmt.Errorf("encode traffic capture: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Flow{}, fmt.Errorf("begin flow insert: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `INSERT INTO flows (
		started_at_ns, duration_ns, client, method, scheme, host, port, path, mode,
		destination_ip, decision, reason, status, bytes_sent, bytes_received,
		bytes_received_decoded, secret_names, policy_trace, response_secret_names,
		capture, session_id, downstream_protocol, upstream_protocol
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.StartedAt.UnixNano(), int64(item.Duration), item.Client, item.Method,
		item.Scheme, item.Host, item.Port, item.Path, item.Mode, item.DestinationIP,
		item.Decision, item.Reason, item.Status, item.BytesSent, item.BytesReceived,
		item.BytesReceivedDecoded, string(secretNames), string(policyTrace), string(responseSecretNames), string(capture), item.SessionID,
		item.DownstreamProtocol, item.UpstreamProtocol)
	if err != nil {
		return Flow{}, fmt.Errorf("insert flow: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return Flow{}, fmt.Errorf("read flow id: %w", err)
	}
	retained := s.retained + 1
	batch := min(retentionBatch, capacity)
	if retained >= capacity+batch {
		if _, err := tx.ExecContext(ctx, deleteOldestSQL, retained-capacity); err != nil {
			return Flow{}, fmt.Errorf("apply flow retention: %w", err)
		}
		retained = capacity
	}
	if err := tx.Commit(); err != nil {
		return Flow{}, fmt.Errorf("commit flow: %w", err)
	}
	s.retained = retained
	item.ID = uint64(id)
	return item, nil
}

const (
	flowSelect = `id, started_at_ns, duration_ns, client, method, scheme, host,
		port, path, mode, destination_ip, decision, reason, status, bytes_sent,
		bytes_received, bytes_received_decoded, secret_names, policy_trace,
		response_secret_names, capture, session_id, downstream_protocol,
		upstream_protocol`
	flowSummarySelect = `id, started_at_ns, duration_ns, client, method, scheme, host,
		port, path, mode, destination_ip, decision, reason, status, bytes_sent,
		bytes_received, bytes_received_decoded, session_id, downstream_protocol,
		upstream_protocol`
)

func (s *sqliteStore) List(ctx context.Context, filter Filter, _ int) ([]Flow, error) {
	return s.list(ctx, filter, flowSelect, scanFlow)
}

func (s *sqliteStore) ListSummary(ctx context.Context, filter Filter, _ int) ([]Flow, error) {
	return s.list(ctx, filter, flowSummarySelect, scanFlowSummary)
}

func (s *sqliteStore) list(ctx context.Context, filter Filter, columns string, scan func(scanner) (Flow, error)) ([]Flow, error) {
	query, args := buildFlowQuery(columns, filter)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list flows: %w", err)
	}
	defer rows.Close()
	items := make([]Flow, 0)
	for rows.Next() {
		item, err := scan(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list flows: %w", err)
	}
	return items, nil
}

func buildFlowQuery(columns string, filter Filter) (string, []any) {
	var query strings.Builder
	query.WriteString("SELECT ")
	query.WriteString(columns)
	query.WriteString(" FROM flows WHERE 1=1")
	args := make([]any, 0, 5)
	for _, condition := range []struct {
		column string
		value  string
	}{
		{"client", filter.Client},
		{"decision", filter.Decision},
		{"mode", filter.Mode},
		{"method", filter.Method},
	} {
		if condition.value != "" {
			query.WriteString(" AND ")
			query.WriteString(condition.column)
			query.WriteString(" = ?")
			args = append(args, condition.value)
		}
	}
	if filter.Host != "" {
		hostPattern := strings.ToLower(strings.TrimSpace(filter.Host))
		if suffix, ok := strings.CutPrefix(hostPattern, "*."); ok {
			query.WriteString(" AND (host = ? OR host LIKE ?)")
			args = append(args, suffix, "%."+suffix)
		} else if strings.ContainsAny(hostPattern, "*?") {
			query.WriteString(" AND host GLOB ?")
			args = append(args, hostPattern)
		} else {
			query.WriteString(" AND host = ?")
			args = append(args, hostPattern)
		}
	}
	if filter.BeforeID != 0 {
		query.WriteString(" AND id < ?")
		args = append(args, int64(filter.BeforeID))
	}
	if len(filter.Sessions) > 0 {
		query.WriteString(" AND session_id IN (")
		for i, session := range filter.Sessions {
			if i > 0 {
				query.WriteString(", ")
			}
			query.WriteString("?")
			args = append(args, session)
		}
		query.WriteString(")")
	}
	query.WriteString(" ORDER BY id DESC LIMIT ?")
	args = append(args, filter.Limit)
	return query.String(), args
}

func (s *sqliteStore) Get(ctx context.Context, id uint64) (Flow, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, started_at_ns, duration_ns, client,
		method, scheme, host, port, path, mode, destination_ip, decision, reason,
		status, bytes_sent, bytes_received, bytes_received_decoded, secret_names,
		policy_trace, response_secret_names, capture, session_id, downstream_protocol,
		upstream_protocol FROM flows WHERE id = ?`, id)
	item, err := scanFlow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Flow{}, false, nil
	}
	if err != nil {
		return Flow{}, false, err
	}
	return item, true, nil
}

func (s *sqliteStore) Close() error { return s.db.Close() }

type scanner interface{ Scan(...any) error }

func scanFlowSummary(row scanner) (Flow, error) {
	var item Flow
	var startedAt, duration int64
	if err := row.Scan(&item.ID, &startedAt, &duration, &item.Client, &item.Method,
		&item.Scheme, &item.Host, &item.Port, &item.Path, &item.Mode,
		&item.DestinationIP, &item.Decision, &item.Reason, &item.Status,
		&item.BytesSent, &item.BytesReceived, &item.BytesReceivedDecoded,
		&item.SessionID, &item.DownstreamProtocol, &item.UpstreamProtocol); err != nil {
		return Flow{}, err
	}
	item.StartedAt = time.Unix(0, startedAt).UTC()
	item.Duration = time.Duration(duration)
	return item, nil
}

func scanFlow(row scanner) (Flow, error) {
	var item Flow
	var startedAt, duration int64
	var secretNames, policyTrace, responseSecretNames, capture string
	if err := row.Scan(&item.ID, &startedAt, &duration, &item.Client, &item.Method,
		&item.Scheme, &item.Host, &item.Port, &item.Path, &item.Mode,
		&item.DestinationIP, &item.Decision, &item.Reason, &item.Status,
		&item.BytesSent, &item.BytesReceived, &item.BytesReceivedDecoded,
		&secretNames, &policyTrace, &responseSecretNames, &capture, &item.SessionID,
		&item.DownstreamProtocol, &item.UpstreamProtocol); err != nil {
		return Flow{}, err
	}
	item.StartedAt = time.Unix(0, startedAt).UTC()
	item.Duration = time.Duration(duration)
	if err := json.Unmarshal([]byte(secretNames), &item.SecretNames); err != nil {
		return Flow{}, fmt.Errorf("decode flow secret names: %w", err)
	}
	if err := json.Unmarshal([]byte(policyTrace), &item.PolicyTrace); err != nil {
		return Flow{}, fmt.Errorf("decode flow policy trace: %w", err)
	}
	if err := json.Unmarshal([]byte(responseSecretNames), &item.ResponseSecretNames); err != nil {
		return Flow{}, fmt.Errorf("decode flow response secret names: %w", err)
	}
	if err := json.Unmarshal([]byte(capture), &item.Capture); err != nil {
		return Flow{}, fmt.Errorf("decode flow traffic capture: %w", err)
	}
	return item, nil
}
