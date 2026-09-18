package stream

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// syncRecorder serialises access so -race sees the heartbeat goroutine's
// writes and the test's reads as ordered.
type syncRecorder struct {
	mu sync.Mutex
	*httptest.ResponseRecorder
}

func (r *syncRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ResponseRecorder.Write(p)
}

func (r *syncRecorder) bodyLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Body.Len()
}

func TestJSONKeepaliveHeartbeatsThenDeliversValidJSON(t *testing.T) {
	rec := &syncRecorder{ResponseRecorder: httptest.NewRecorder()}
	k := NewJSONKeepalive(context.Background(), rec)
	k.Interval = 5 * time.Millisecond
	committed := false
	k.Start(func() { committed = true })
	time.Sleep(40 * time.Millisecond)
	k.Deliver([]byte(`{"id":"r"}`), nil)

	if !committed || rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("commit=%v code=%d ct=%q", committed, rec.Code, rec.Header().Get("Content-Type"))
	}
	body := rec.Body.Bytes()
	if len(body) == 0 || body[0] != ' ' {
		t.Fatalf("no heartbeat before body: %q", body)
	}
	var v map[string]any
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&v); err != nil || v["id"] != "r" {
		t.Fatalf("leading whitespace broke JSON: %v %q", err, body)
	}
	n := rec.bodyLen()
	time.Sleep(20 * time.Millisecond)
	if rec.bodyLen() != n {
		t.Fatal("heartbeat kept writing after Deliver")
	}
}

func TestJSONKeepaliveStartWritesABodyByteImmediately(t *testing.T) {
	rec := httptest.NewRecorder()
	k := NewJSONKeepalive(context.Background(), rec)
	k.Interval = time.Hour
	k.Start(nil)
	if rec.Body.String() != " " || !rec.Flushed {
		t.Fatalf("Start must write and flush one byte at once: %q flushed=%v", rec.Body.String(), rec.Flushed)
	}
	k.Stop()
}

func TestJSONKeepaliveUncommittedIsPlainReply(t *testing.T) {
	rec := httptest.NewRecorder()
	k := NewJSONKeepalive(context.Background(), rec)
	k.Deliver([]byte(`{"ok":true}`), func() { rec.Header().Set("X-Test", "1") })
	if rec.Code != http.StatusOK || rec.Body.String() != `{"ok":true}` || rec.Header().Get("X-Test") != "1" {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestJSONKeepaliveStopPreventsLateStart(t *testing.T) {
	rec := httptest.NewRecorder()
	k := NewJSONKeepalive(context.Background(), rec)
	if k.Stop() {
		t.Fatal("reported committed without Start")
	}
	k.Start(nil)
	if k.Committed() || rec.Body.Len() != 0 {
		t.Fatal("Start after Stop committed the response")
	}
}

func TestJSONKeepaliveFailWritesErrorBody(t *testing.T) {
	rec := httptest.NewRecorder()
	k := NewJSONKeepalive(context.Background(), rec)
	k.Start(nil)
	k.Fail("service_response_error", "stopped")
	var v struct {
		Error struct{ Code, Message string } `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(rec.Body.Bytes()), &v); err != nil || v.Error.Code != "service_response_error" {
		t.Fatalf("error body = %q (%v)", rec.Body.String(), err)
	}
}
