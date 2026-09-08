package codexws

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// Pooling upstream Codex WebSockets across turns.
//
// # Why a pool is not optional
//
// A WebSocket that is dialed and closed per request is strictly WORSE than the
// HTTP path it would replace. The HTTP path already reuses connections —
// auth.ClientFor hands out one pooled h2 transport per proxy URL, so a busy
// account carries many requests over few TCP/TLS handshakes. Dialing a fresh
// WebSocket per turn would invert that: one TLS handshake per turn, against the
// same Cloudflare edge that rate-limits new connections from datacentre IPs and
// RSTs the handshake once the per-IP quota is hit. That is the alternating
// 200/503 symptom, and a naive WS egress would make it worse, not better.
//
// So the transport's advantages — protocol-level ping/pong across the silent
// gaps that truncate an idle SSE stream, and matching what a current codex-tui
// actually does — are only reachable with connection reuse. Hence this file.
//
// # Lease semantics
//
// gorilla permits one concurrent reader and one concurrent writer per
// connection, and a Codex turn uses both for its whole duration. A pooled
// connection therefore serves one turn at a time: Acquire hands out an
// exclusive lease, and a second caller arriving while the connection is busy
// gets a fresh EPHEMERAL connection that is closed on release rather than
// pooled. Queueing behind the busy one instead would convert a user's
// concurrent turns into serial ones.

const (
	defaultPoolIdleTTL = 5 * time.Minute
	// defaultPoolMaxAge bounds a connection's total life. Just under an hour,
	// which is where the backend has been observed to retire long-lived
	// sockets; retiring ours first turns a mid-turn server close into an
	// orderly reconnect between turns.
	defaultPoolMaxAge = 55 * time.Minute
)

// PoolConfig tunes connection retention.
type PoolConfig struct {
	// IdleTTL closes a pooled connection left unused for this long. 0 => 5m.
	IdleTTL time.Duration
	// MaxAge closes a connection this long after it was dialed, at the next
	// release or acquire. 0 => 55m.
	MaxAge time.Duration
	// MaxEntries caps pooled (idle or busy) connections. 0 => unlimited.
	// Reaching the cap does not fail an acquire; it serves it ephemerally.
	MaxEntries int
}

// DialFunc opens one upstream connection. The pool calls it without holding its
// lock, so a slow handshake never blocks acquires for other keys.
type DialFunc func(ctx context.Context) (Conn, *http.Response, error)

// Pool keeps upstream Codex WebSockets alive across turns, keyed by whatever
// string the caller uses to name one logical conversation on one credential.
//
// The key MUST include the credential and the downstream tenant. A connection
// carries the account's bearer and the session id that names the upstream
// prompt cache, so two tenants sharing a key would share a cache namespace and
// a turn's worth of context.
type Pool struct {
	cfg PoolConfig

	mu      sync.Mutex
	entries map[string]*poolEntry
	closed  bool
}

type poolEntry struct {
	conn      Conn
	busy      bool
	createdAt time.Time
	idleTimer *time.Timer
}

// Lease is exclusive use of one connection for one turn.
type Lease struct {
	Conn Conn
	// Reused is true when the connection was already open. A turn on a reused
	// connection that produces no frames at all is the signature of a socket the
	// server closed while idle, and the caller should retry once on a fresh one.
	Reused bool
	// Handshake is the upstream 101 response, present only on a fresh dial.
	Handshake *http.Response

	pool     *Pool
	key      string
	entry    *poolEntry
	released bool
}

// NewPool returns a pool with cfg's zero values filled in.
func NewPool(cfg PoolConfig) *Pool {
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = defaultPoolIdleTTL
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = defaultPoolMaxAge
	}
	return &Pool{cfg: cfg, entries: map[string]*poolEntry{}}
}

// Acquire leases a connection for key, dialing one if none is reusable.
//
// An empty key is served ephemerally: without a name there is nothing to reuse
// the connection for, and pooling it under "" would hand one conversation's
// socket to an unrelated one.
func (p *Pool) Acquire(ctx context.Context, key string, dial DialFunc) (*Lease, error) {
	if key == "" {
		return p.dialEphemeral(ctx, "", dial)
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return p.dialEphemeral(ctx, key, dial)
	}
	if e := p.entries[key]; e != nil {
		switch {
		case e.busy:
			// Concurrent turn on the same conversation. Serve it on its own
			// socket rather than serializing behind this one.
			p.mu.Unlock()
			return p.dialEphemeral(ctx, key, dial)
		case time.Since(e.createdAt) >= p.cfg.MaxAge:
			p.dropLocked(key, e)
		default:
			e.busy = true
			p.stopIdleLocked(e)
			p.mu.Unlock()
			// Probe before handing it over. A write-only ping costs one control
			// frame and catches a socket the server (or an intermediary) closed
			// while it sat idle, which is otherwise only discovered by burning
			// the turn's first read. Any pong that comes back is absorbed by
			// gorilla's default handler during the turn's own reads.
			if err := e.conn.Ping(time.Now().Add(5 * time.Second)); err != nil {
				p.mu.Lock()
				p.dropLocked(key, e)
				p.mu.Unlock()
				return p.dialAndPool(ctx, key, dial)
			}
			return &Lease{Conn: e.conn, Reused: true, pool: p, key: key, entry: e}, nil
		}
	}
	if p.cfg.MaxEntries > 0 && len(p.entries) >= p.cfg.MaxEntries {
		p.mu.Unlock()
		return p.dialEphemeral(ctx, key, dial)
	}
	p.mu.Unlock()
	return p.dialAndPool(ctx, key, dial)
}

func (p *Pool) dialEphemeral(ctx context.Context, key string, dial DialFunc) (*Lease, error) {
	conn, resp, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	return &Lease{Conn: conn, Handshake: resp, pool: p, key: key}, nil
}

func (p *Pool) dialAndPool(ctx context.Context, key string, dial DialFunc) (*Lease, error) {
	conn, resp, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	e := &poolEntry{conn: conn, busy: true, createdAt: time.Now()}

	p.mu.Lock()
	if p.closed || p.entries[key] != nil {
		// Either the pool shut down under us, or a concurrent acquire for the
		// same key won the race and installed its own. Ours stays unpooled
		// rather than evicting a connection someone is mid-turn on.
		p.mu.Unlock()
		return &Lease{Conn: conn, Handshake: resp, pool: p, key: key}, nil
	}
	p.entries[key] = e
	p.mu.Unlock()
	return &Lease{Conn: conn, Handshake: resp, pool: p, key: key, entry: e}, nil
}

// Release returns the lease. keep=false closes the connection outright, which
// is what every abnormal end of a turn must do: a socket whose turn did not
// reach a terminal event may still have that turn's frames queued on it, and
// handing it to the next turn would deliver them as if they belonged to it.
func (l *Lease) Release(keep bool) {
	if l == nil || l.released {
		return
	}
	l.released = true
	p := l.pool
	if l.entry == nil {
		closeQuietly(l.Conn)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	e := l.entry
	if !keep || p.closed || time.Since(e.createdAt) >= p.cfg.MaxAge {
		p.dropLocked(l.key, e)
		return
	}
	e.busy = false
	p.stopIdleLocked(e)
	key := l.key
	e.idleTimer = time.AfterFunc(p.cfg.IdleTTL, func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if cur := p.entries[key]; cur == e && !e.busy {
			p.dropLocked(key, e)
		}
	})
}

// Close shuts the pool and closes every connection it holds. Busy connections
// are closed too: the caller is shutting down, and a turn in flight is going to
// end with the process either way.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for key, e := range p.entries {
		p.dropLocked(key, e)
	}
}

// Len reports how many connections the pool currently holds.
func (p *Pool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

func (p *Pool) dropLocked(key string, e *poolEntry) {
	p.stopIdleLocked(e)
	if cur := p.entries[key]; cur == e {
		delete(p.entries, key)
	}
	closeQuietly(e.conn)
}

func (p *Pool) stopIdleLocked(e *poolEntry) {
	if e.idleTimer != nil {
		e.idleTimer.Stop()
		e.idleTimer = nil
	}
}

func closeQuietly(c Conn) {
	if c != nil {
		_ = c.Close()
	}
}
