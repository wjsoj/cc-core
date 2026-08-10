// Package relay carries the identity of a downstream caller across one trusted
// proxy hop, so the receiving proxy can spread load the way it would if the
// callers had connected to it directly.
//
// The problem it solves: when proxy A forwards to proxy B using a single API
// key, B sees one client. Its credential scheduler keys sticky assignments on
// (provider, client token, session), so every user behind A collapses onto one
// upstream credential no matter how many are free — and A's users get the
// throughput of one account while B's pool sits idle.
//
// A stamps the three headers below; B recovers them and uses them for ROUTING
// ONLY. Rate limits, quotas and billing stay keyed on the relay's own token,
// because the relay is one paying customer however many users sit behind it —
// and because a limit keyed on a header is a limit anyone can evade by
// inventing a new value.
//
// # Trust
//
// These headers are self-asserted. A receiver MUST honour them only from a
// caller it has independently authenticated as a trusted relay (in this
// codebase: a client token flagged trusted_relay), and MUST Strip them from
// every other request so a direct caller cannot impersonate one. A sender MUST
// stamp them only on credentials it knows point at a cooperating peer — to
// anyone else they are noise that leaks the topology.
package relay

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

const (
	// HeaderPeer names the relay software and version, e.g. "cpa-claude/0.19.85".
	// Informational: the receiver's trust decision comes from authentication,
	// never from this value.
	HeaderPeer = "X-Relay-Client-Peer"
	// HeaderClient is an opaque, stable id for the downstream caller — see
	// ClientID. It is a hash, so the receiver can tell users apart without
	// learning the sender's credentials.
	HeaderClient = "X-Relay-Client-Id"
	// HeaderSession is the downstream caller's own session/slot id, i.e. what
	// the CLI sent as X-Claude-Code-Session-Id / Session_id. Empty when the
	// caller is a raw API client with no session concept.
	HeaderSession = "X-Relay-Client-Session"
)

// maxValue bounds a recovered value. These become map keys in the receiver's
// scheduler, so an unbounded header would be an unbounded allocation.
const maxValue = 128

// ClientID renders a downstream client token as a stable opaque id.
//
// Hashing rather than forwarding the token is not ceremony: the two proxies
// have separate token namespaces and separate operators-of-record, and the
// receiver needs only to tell callers apart. A leaked log line on the receiving
// side must not be a credential on the sending side.
func ClientID(clientToken string) string {
	clientToken = strings.TrimSpace(clientToken)
	if clientToken == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("cc-core/relay/client\x00" + clientToken))
	return hex.EncodeToString(sum[:8])
}

// Apply stamps a downstream caller's identity onto an upstream request.
//
// It always clears the headers first: the sender's own ingress may have carried
// them (a caller trying to impersonate a relay), and a stale value would be
// worse than none. Pass clientToken as the raw downstream token — hashing is
// done here so no caller has to remember to.
func Apply(h http.Header, peer, clientToken, sessionID string) {
	Strip(h)
	id := ClientID(clientToken)
	if id == "" {
		// Nothing to identify: an unidentified caller must not be given a
		// blank identity that every other unidentified caller also shares.
		return
	}
	if peer = sanitize(peer); peer != "" {
		h.Set(HeaderPeer, peer)
	}
	h.Set(HeaderClient, id)
	if s := sanitize(sessionID); s != "" {
		h.Set(HeaderSession, s)
	}
}

// Strip removes the headers. Receivers MUST call this on every request from a
// caller that is not an authenticated trusted relay.
func Strip(h http.Header) {
	h.Del(HeaderPeer)
	h.Del(HeaderClient)
	h.Del(HeaderSession)
}

// Identity is the downstream caller a trusted relay declared.
type Identity struct {
	Peer    string
	Client  string
	Session string
}

// Read recovers the identity a relay stamped. ok is false when no usable client
// id is present, in which case the request should be treated as coming from the
// relay itself.
//
// Call this ONLY after authenticating the caller as a trusted relay.
func Read(h http.Header) (Identity, bool) {
	id := Identity{
		Peer:    sanitize(h.Get(HeaderPeer)),
		Client:  sanitize(h.Get(HeaderClient)),
		Session: sanitize(h.Get(HeaderSession)),
	}
	if id.Client == "" {
		return Identity{}, false
	}
	return id, true
}

// SlotID renders the scheduler session key for a relayed request: one slot per
// (downstream user, downstream session), which is exactly what the user would
// have presented had they connected directly.
//
// A caller with no session of its own still gets a per-user slot rather than
// sharing one global slot with every other such caller.
func (id Identity) SlotID() string {
	if id.Client == "" {
		return ""
	}
	return id.Client + "/" + id.Session
}

// sanitize keeps a header value usable as a map key and safe to log: printable
// ASCII, no separators that would let one field forge another, length-bounded.
// Anything else is dropped whole rather than mangled — a partially-decoded
// identity is worse than an absent one.
func sanitize(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > maxValue {
		return ""
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == ':' || c == '/'
		if !ok {
			return ""
		}
	}
	return v
}
