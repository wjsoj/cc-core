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
	// CacheCreate1h is the 1-hour-TTL SUBSET of CacheCreate (Anthropic's
	// `usage.cache_creation.ephemeral_1h_input_tokens`). Omitted when the
	// upstream reports no breakdown, so older rows and non-Anthropic providers
	// are unaffected. Recorded ahead of any pricing decision: a 1h write costs
	// 2× input against a 5m write's 1.25×, and mimicry sets ttl:"1h" on every
	// breakpoint, so this column is what makes the two separable in an audit.
	// Never subtract it from CacheCreate — CacheCreate stays the full total.
	CacheCreate1h int64   `json:"cache_create_1h_tokens,omitempty"`
	CostUSD       float64 `json:"cost_usd"`
	Status        int     `json:"status"`
	DurationMs    int64   `json:"duration_ms"`
	Stream        bool    `json:"stream"`
	Path          string  `json:"path,omitempty"`
	Attempts      int     `json:"attempts,omitempty"` // credential attempts before terminal
	Error         string  `json:"error,omitempty"`
	// AttemptOnly marks a credential-attempt audit row that was withheld from
	// the client and followed by failover. Dashboard/query aggregates ignore
	// these rows so retry telemetry does not inflate user-visible counts.
	AttemptOnly bool `json:"attempt_only,omitempty"`
	// ClaudeAudit contains only policy outcomes and a domain-separated account
	// digest. It never stores an account UUID, email, prompt, bearer, or client
	// token.
	ClaudeAudit *ClaudeAudit `json:"claude_audit,omitempty"`

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

// ClaudeAudit is privacy-safe evidence of Claude request preparation, identity
// mapping, and any local fallback decision.
type ClaudeAudit struct {
	AccountHash           string   `json:"account_hash,omitempty"`
	ClientHash            string   `json:"client_hash,omitempty"`
	RequestClass          string   `json:"request_class"`
	IdentityMode          string   `json:"identity_mode"`
	AccountIdentityMapped bool     `json:"account_identity_mapped"`
	CredentialHardFailed  bool     `json:"credential_hard_failed,omitempty"`
	PreparationFailed     bool     `json:"preparation_failed,omitempty"`
	PreparationError      string   `json:"preparation_error,omitempty"`
	PreparationFailures   int      `json:"preparation_failures,omitempty"`
	Fallback              string   `json:"fallback,omitempty"`
	BodyBytes             int      `json:"body_bytes,omitempty"`
	BodySHA256            string   `json:"body_sha256,omitempty"`
	SessionBinding        string   `json:"session_binding,omitempty"`
	BillingValidation     string   `json:"billing_validation,omitempty"`
	BetaHash              string   `json:"beta_hash,omitempty"`
	ProfileHash           string   `json:"profile_hash,omitempty"`
	ProxyConfigHash       string   `json:"proxy_config_hash,omitempty"`
	ExtraMetadataCount    int      `json:"extra_metadata_count,omitempty"`
	ExtraHeaderCount      int      `json:"extra_header_count,omitempty"`
	ExtraMetadataKeys     []string `json:"extra_metadata_keys,omitempty"`
	ExtraHeaderNames      []string `json:"extra_header_names,omitempty"`
}

// BilledOrCost returns what the customer actually paid, tolerating both log
// generations in one directory.
//
// Until v0.8.61 one fork wrote the billed amount into CostUSD and left
// BilledUSD unset, while the other wrote the official price into CostUSD and
// the debit into BilledUSD — the same column meaning opposite things depending
// on which binary produced the row. Both now use the second convention, but a
// 90-day retention window means mixed files for a quarter.
//
// Reading BilledUSD when non-zero and CostUSD otherwise resolves to the charged
// amount under either convention, which is what every spend/reconciliation view
// wants. Writers set both fields together, so a zero BilledUSD on a new row
// means the request was not billed at all — and CostUSD is zero there too, so
// the fallback returns 0 rather than inventing a charge.
func (r Record) BilledOrCost() float64 {
	if r.BilledUSD != 0 {
		return r.BilledUSD
	}
	return r.CostUSD
}

type Writer struct {
	dir           string
	retentionDays int
	jsonl         bool
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
	// curOff is the byte offset the next record will be written at. O_APPEND
	// hides the position from us, so it is tracked here — it is what pairs a
	// record with the JSONL line it became, and thus what lets the index
	// deduplicate against its own later re-read of that line.
	curOff int64

	// noStoreWarned keeps the "archive off but no index" complaint to once
	// per writer rather than once per batch.
	noStoreWarned atomic.Bool
}

// Options configures a Writer. The zero value is not useful; use Open for the
// historical defaults.
type Options struct {
	// RetentionDays <= 0 disables retention entirely.
	RetentionDays int
	// JSONLArchive keeps the daily-rotated .jsonl files. With an index open,
	// turning this off makes SQLite the only copy: nothing rebuilds it, and a
	// failed insert is a lost record. It exists so an operator who trusts the
	// index can stop paying for two copies — not as a default.
	JSONLArchive bool
}

// Open creates the writer with the historical behaviour (JSONL archive on)
// and starts a background goroutine that drains the channel. dir will be
// created if missing. retentionDays <= 0 disables GC.
func Open(dir string, retentionDays int) (*Writer, error) {
	return OpenWithOptions(dir, Options{RetentionDays: retentionDays, JSONLArchive: true})
}

// OpenWithOptions is Open with the archive switch exposed.
//
// When JSONLArchive is false the caller must have opened the index for this
// directory first: the writer has nowhere else to put a record, and OpenStore
// is what makes that destination exist.
func OpenWithOptions(dir string, opt Options) (*Writer, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("requestlog: empty dir")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	st := lookupStore(dir)
	if !opt.JSONLArchive && st == nil {
		return nil, fmt.Errorf("requestlog: jsonl archive disabled but no index open for %s", dir)
	}
	// Tell the index whether the files are authoritative BEFORE the writer
	// starts, so no catch-up can read a stale ledger entry as a retention
	// delete and drop the rows behind it.
	st.setArchiveMode(opt.JSONLArchive)
	w := &Writer{
		dir:           dir,
		retentionDays: opt.RetentionDays,
		jsonl:         opt.JSONLArchive,
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

// Shutdown closes a writer and its index in the only order that cannot lose
// records.
//
// The writer must go first. Its Close blocks until the drain goroutine has
// flushed what is still buffered, and that flush resolves its destination by
// looking the store up by directory — so a store closed first has already
// deregistered itself, and under Options{JSONLArchive: false} the batch has
// nowhere left to go and is counted as dropped. There is no file to recover it
// from; that is the whole trade of index-only mode.
//
// Closing the writer first is equally safe with the archive on. The concern that
// motivated the opposite order — the index's file tailing racing the final
// flush — is already handled by the unique (src_file, src_off) key: whichever
// producer offers a line second is a no-op.
//
// Both arguments may be nil.
func Shutdown(w *Writer, st *Store) {
	w.Close()
	st.Close()
}

// dbBatch is how many records accumulate before being inserted into the index
// in one transaction. The flush ticker bounds the latency for a quiet stream,
// so this only has to be large enough that a busy one is not paying per-record
// transaction overhead.
const dbBatch = 500

func (w *Writer) loop() {
	defer close(w.doneCh)
	flushTicker := time.NewTicker(5 * time.Second)
	defer flushTicker.Stop()

	// Records written but not yet folded into the index. Held here rather
	// than inserted per record so the index sees one transaction per batch.
	pending := make([]pendingRow, 0, dbBatch)

	flushDB := func() {
		if len(pending) == 0 {
			return
		}
		batch := pending
		pending = make([]pendingRow, 0, dbBatch)
		st := lookupStore(w.dir)
		if st == nil {
			// With the archive on this is normal and harmless: the index is
			// not open yet (or is disabled), and the scanner will pick these
			// lines up from the file. With it off, the records are gone.
			if !w.jsonl {
				w.dropped.Add(int64(len(batch)))
				if !w.noStoreWarned.Swap(true) {
					log.Errorf("requestlog: no index open for %s and jsonl archive is off; records are being dropped", w.dir)
				}
			}
			return
		}
		if err := st.appendRows(batch); err != nil {
			log.Errorf("requestlog: index append (%d records): %v", len(batch), err)
			if !w.jsonl {
				w.dropped.Add(int64(len(batch)))
			}
			// With the archive on, the scanner re-reads these lines from the
			// file, so the loss is temporary and self-repairing.
		}
	}

	flush := func() {
		w.mu.Lock()
		if w.curFile != nil {
			_ = w.curFile.Sync()
		}
		w.mu.Unlock()
		flushDB()
	}

	for {
		select {
		case <-w.stopCh:
			for {
				select {
				case r := <-w.ch:
					if p, ok := w.writeRecord(r); ok {
						pending = append(pending, p)
					}
				default:
					flush()
					w.closeFile()
					return
				}
			}
		case r := <-w.ch:
			if p, ok := w.writeRecord(r); ok {
				pending = append(pending, p)
				if len(pending) >= dbBatch {
					flushDB()
				}
			}
		case <-flushTicker.C:
			flush()
		}
	}
}

// writeRecord appends one record to the archive and reports where it landed,
// so the caller can hand the index the same (file, offset) the scanner would
// later derive. ok is false only when the record could not be recorded at all.
func (w *Writer) writeRecord(r Record) (pendingRow, bool) {
	day := r.TS.UTC().Format("2006-01-02")
	if !w.jsonl {
		// No file, so no offset to deduplicate against. src_off = -1 keeps the
		// row out of the unique index, which is correct: nothing will ever
		// re-read this record from anywhere.
		w.maybeGC(day)
		return pendingRow{rec: r, off: -1}, true
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.curFile == nil || w.curDay != day {
		w.closeFileLocked()
		path := filepath.Join(w.dir, "requests-"+day+".jsonl")
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			log.Errorf("requestlog: open %s: %v", path, err)
			return pendingRow{}, false
		}
		// Resume the offset from the file's current length: a restart appends
		// to yesterday's or today's existing file, and an offset restarting at
		// zero would collide with rows the previous run already indexed.
		off := int64(0)
		if fi, err := f.Stat(); err == nil {
			off = fi.Size()
		}
		w.curFile = f
		w.curDay = day
		w.curOff = off
		go w.gc()
	}
	data, err := json.Marshal(r)
	if err != nil {
		return pendingRow{}, false
	}
	data = append(data, '\n')
	at := w.curOff
	n, err := w.curFile.Write(data)
	w.curOff += int64(n)
	if err != nil {
		log.Errorf("requestlog: write: %v", err)
		// A short write leaves a torn line the scanner will skip; do not hand
		// the index a row claiming to live at an offset that holds garbage.
		return pendingRow{}, false
	}
	return pendingRow{rec: r, file: "requests-" + day + ".jsonl", off: at}, true
}

// maybeGC triggers retention on day change when there is no file rotation to
// hang it off.
func (w *Writer) maybeGC(day string) {
	w.mu.Lock()
	changed := w.curDay != day
	w.curDay = day
	w.mu.Unlock()
	if changed {
		go w.gc()
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

// gc deletes log files older than retentionDays, and prunes the index to the
// same cutoff. Runs on rotation (cheap).
//
// The index prune is not merely an optimisation of the scanner's own
// missing-file handling: with the archive off there is no file whose absence
// could signal expiry, so this is what enforces retention at all.
func (w *Writer) gc() {
	if w.retentionDays <= 0 {
		return
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -w.retentionDays).Format("2006-01-02")
	if st := lookupStore(w.dir); st != nil {
		if err := st.pruneBefore(cutoff); err != nil {
			log.Warnf("requestlog: index prune before %s: %v", cutoff, err)
		}
	}
	if !w.jsonl {
		return
	}
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
//
// The index is updated with a single UPDATE rather than by re-reading the
// rewritten files. Without that, changing one field would cost a re-parse of
// the entire archive: the scanner treats any change to a rotated file as
// tampering, and every file it just rewrote qualifies.
func (w *Writer) RewriteClientMask(oldMask, newMask string) (int, error) {
	if oldMask == "" || newMask == "" || oldMask == newMask {
		return 0, fmt.Errorf("oldMask and newMask must differ and be non-empty")
	}
	w.mu.Lock()
	w.closeFileLocked()
	w.mu.Unlock()

	total := 0
	if w.jsonl {
		entries, err := os.ReadDir(w.dir)
		if err != nil {
			return 0, err
		}
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
	}

	st := lookupStore(w.dir)
	if st == nil {
		return total, nil
	}
	// Count from the index when there were no files to count from.
	if !w.jsonl {
		_ = st.db.QueryRow(`SELECT COUNT(*) FROM req WHERE client_token = ?`, oldMask).Scan(&total)
	}
	if err := st.rewriteClientMask(oldMask, newMask); err != nil {
		return total, fmt.Errorf("index rewrite: %w", err)
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
