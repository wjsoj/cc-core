// Package requestlog writes one JSON line per terminal request to a daily-
// rotated file. Writes are buffered through a channel so the hot path isn't
// blocked on I/O.
//
// # Record schema
//
// Record is the unified wire format shared across CPA-Claude (single-user)
// and hypitoken (multi-tenant SaaS). Optional SaaS fields (UserID,
// BilledUSD, Multiplier) carry json:",omitempty" so single-user deployments
// produce identical JSONL output as before.
//
// # Compatibility
//
// On-disk filenames (`requests-YYYY-MM-DD.jsonl`) and Record JSON shape
// are preserved verbatim from the original CPA-Claude implementation so
// existing log directories can be upgraded in place without migration.
// Older rotated rows without the new fields parse correctly via Go's
// default zero-value semantics.
package requestlog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// Record is one line in the log.
type Record struct {
	TS          time.Time `json:"ts"`
	Client      string    `json:"client,omitempty"`   // friendly token name
	ClientToken string    `json:"client_token"`       // masked
	Provider    string    `json:"provider,omitempty"` // "anthropic" | "openai"; empty on legacy records
	AuthID      string    `json:"auth_id"`
	AuthLabel   string    `json:"auth_label,omitempty"`
	AuthKind    string    `json:"auth_kind"` // "oauth" or "apikey"
	Model       string    `json:"model"`
	Input       int64     `json:"input_tokens"`
	Output      int64     `json:"output_tokens"`
	CacheRead   int64     `json:"cache_read_tokens"`
	CacheCreate int64     `json:"cache_create_tokens"`
	CostUSD     float64   `json:"cost_usd"`
	Status      int       `json:"status"`
	DurationMs  int64     `json:"duration_ms"`
	Stream      bool      `json:"stream"`
	Path        string    `json:"path,omitempty"`
	Attempts    int       `json:"attempts,omitempty"` // credential attempts before terminal
	Error       string    `json:"error,omitempty"`

	// SaaS-tier optional fields. Zero on requests that didn't go through
	// a billing/multi-tenant layer.
	//
	// BilledUSD is what was actually debited from the client's wallet,
	// typically CostUSD scaled by Multiplier. Zero on plain CPA-Claude.
	BilledUSD float64 `json:"billed_usd,omitempty"`
	// Multiplier is the pricing-group coefficient that produced
	// BilledUSD. Stored alongside so historical audits can verify each
	// bill line against the catalog rate, immune to subsequent group
	// config changes.
	Multiplier float64 `json:"multiplier,omitempty"`
	// UserID identifies the SaaS account this request belongs to (used
	// by per-user dashboards to filter to just that account's history).
	UserID int64 `json:"user_id,omitempty"`
}

type Writer struct {
	dir           string
	retentionDays int
	ch            chan Record
	stopCh        chan struct{}
	doneCh        chan struct{}

	// dropped counts records discarded because the buffer was full (slow
	// disk / sustained burst). Exposed via Dropped() so the host can surface
	// it as a health metric instead of losing log lines silently.
	dropped atomic.Int64

	mu      sync.Mutex
	curFile *os.File
	curDay  string
}

// Open creates the writer, starts a background goroutine that drains the
// channel. dir will be created if missing. retentionDays <= 0 disables GC.
func Open(dir string, retentionDays int) (*Writer, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("requestlog: empty dir")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	w := &Writer{
		dir:           dir,
		retentionDays: retentionDays,
		ch:            make(chan Record, 4096),
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
	go w.loop()
	return w, nil
}

// Log enqueues a record. Non-blocking: if the buffer is full (slow disk,
// burst), the oldest pending entry is dropped to make room rather than
// blocking the hot path.
func (w *Writer) Log(r Record) {
	if w == nil {
		return
	}
	if r.TS.IsZero() {
		r.TS = time.Now()
	}
	select {
	case w.ch <- r:
	default:
		// Buffer full: drop the oldest pending entry to make room for the
		// newer one, and count the loss. Never block the hot path.
		select {
		case <-w.ch:
			w.dropped.Add(1)
		default:
		}
		select {
		case w.ch <- r:
		default:
			w.dropped.Add(1)
		}
	}
}

// Dropped returns the cumulative number of records discarded because the
// write buffer was full. A non-zero, growing value means the disk can't keep
// up with the request rate (or the buffer needs raising).
func (w *Writer) Dropped() int64 {
	if w == nil {
		return 0
	}
	return w.dropped.Load()
}

// Close flushes pending entries, fsyncs and closes the current file.
// Safe to call multiple times.
func (w *Writer) Close() {
	if w == nil {
		return
	}
	select {
	case <-w.stopCh:
		return
	default:
		close(w.stopCh)
	}
	<-w.doneCh
}

func (w *Writer) loop() {
	defer close(w.doneCh)
	flushTicker := time.NewTicker(5 * time.Second)
	defer flushTicker.Stop()

	flush := func() {
		w.mu.Lock()
		if w.curFile != nil {
			_ = w.curFile.Sync()
		}
		w.mu.Unlock()
	}

	for {
		select {
		case <-w.stopCh:
			for {
				select {
				case r := <-w.ch:
					w.writeRecord(r)
				default:
					flush()
					w.closeFile()
					return
				}
			}
		case r := <-w.ch:
			w.writeRecord(r)
		case <-flushTicker.C:
			flush()
		}
	}
}

func (w *Writer) writeRecord(r Record) {
	day := r.TS.UTC().Format("2006-01-02")
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.curFile == nil || w.curDay != day {
		w.closeFileLocked()
		path := filepath.Join(w.dir, "requests-"+day+".jsonl")
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			log.Errorf("requestlog: open %s: %v", path, err)
			return
		}
		w.curFile = f
		w.curDay = day
		go w.gc()
	}
	data, err := json.Marshal(r)
	if err != nil {
		return
	}
	data = append(data, '\n')
	if _, err := w.curFile.Write(data); err != nil {
		log.Errorf("requestlog: write: %v", err)
	}
}

func (w *Writer) closeFileLocked() {
	if w.curFile != nil {
		_ = w.curFile.Sync()
		_ = w.curFile.Close()
		w.curFile = nil
		w.curDay = ""
	}
}

func (w *Writer) closeFile() {
	w.mu.Lock()
	w.closeFileLocked()
	w.mu.Unlock()
}

// gc deletes log files older than retentionDays. Runs on rotation (cheap).
func (w *Writer) gc() {
	if w.retentionDays <= 0 {
		return
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -w.retentionDays).Format("2006-01-02")
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "requests-") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		day := strings.TrimSuffix(strings.TrimPrefix(name, "requests-"), ".jsonl")
		if day < cutoff {
			_ = os.Remove(filepath.Join(w.dir, name))
		}
	}
}

// RewriteClientMask rewrites every record with ClientToken == oldMask to
// have ClientToken == newMask, across all rotated JSONL files in the log
// directory. Used by admin token-reset to migrate historical telemetry
// when a token is rotated.
//
// The current-day file is closed under mutex before rewrite and will be
// recreated on the next Log() call. Each file is rewritten via a temp
// file + atomic rename so a crash mid-rewrite never produces a half-
// rewritten log. Returns the number of rewritten records.
func (w *Writer) RewriteClientMask(oldMask, newMask string) (int, error) {
	if oldMask == "" || newMask == "" || oldMask == newMask {
		return 0, fmt.Errorf("oldMask and newMask must differ and be non-empty")
	}
	w.mu.Lock()
	w.closeFileLocked()
	w.mu.Unlock()

	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		path := filepath.Join(w.dir, e.Name())
		n, err := rewriteMaskFile(path, oldMask, newMask)
		if err != nil {
			return total, fmt.Errorf("rewrite %s: %w", e.Name(), err)
		}
		total += n
	}
	return total, nil
}

func rewriteMaskFile(path, oldMask, newMask string) (int, error) {
	in, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	tmpPath := path + ".rewrite.tmp"
	out, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return 0, err
	}
	dec := json.NewDecoder(in)
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	hits := 0
	for dec.More() {
		var r Record
		if err := dec.Decode(&r); err != nil {
			out.Close()
			os.Remove(tmpPath)
			return 0, err
		}
		if r.ClientToken == oldMask {
			r.ClientToken = newMask
			hits++
		}
		if err := enc.Encode(&r); err != nil {
			out.Close()
			os.Remove(tmpPath)
			return 0, err
		}
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmpPath)
		return 0, err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmpPath)
		return 0, err
	}
	if hits == 0 {
		os.Remove(tmpPath)
		return 0, nil
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return 0, err
	}
	return hits, nil
}
