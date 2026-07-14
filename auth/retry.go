package auth

import (
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"syscall"
	"time"
)

// transientRetryBackoffs is the per-attempt base delay before replaying a
// transient wire-level failure on the SAME upstream connection/credential.
// Exponential-ish with a hard ceiling; per-attempt jitter (see RoundTrip) is
// layered on top so a batch of connections that a Cloudflare edge RST'd at the
// same instant don't all retry in lockstep and re-trip the rate limiter.
//
// len(transientRetryBackoffs) == max retries. Total worst-case added latency is
// the sum (~5s) and is always bounded by the request context — if the client
// gives up, the loop stops immediately.
var transientRetryBackoffs = []time.Duration{
	300 * time.Millisecond,
	700 * time.Millisecond,
	1400 * time.Millisecond,
	2500 * time.Millisecond,
}

// transientErrFragments are substrings of error messages that mean the upstream
// connection flapped, not that the credential is bad. Kept as plain substring
// matches because the h2 stack wraps these in several layers (e.g.
// "stream error: stream ID 23; PROTOCOL_ERROR; received from peer") and a
// handshake reset reaches us as "utls handshake chatgpt.com: read tcp ...:
// read: connection reset by peer".
var transientErrFragments = []string{
	"connection reset by peer",
	"broken pipe",
	"unexpected EOF",
	"http2: server sent GOAWAY",
	// h2 stream errors the peer sent us — chatgpt.com's CF edge rejecting a
	// stream on a reused connection. The server did NOT process the request, so
	// replaying it is safe. REFUSED_STREAM is the explicit "didn't start it"
	// code; PROTOCOL_ERROR is what CF returns when it tears a stream down.
	"PROTOCOL_ERROR",
	"REFUSED_STREAM",
	// A pooled h2 ClientConn whose underlying SOCKS5 tunnel died silently (an
	// idle-killed tunnel on a cheap relay, or an RST between our
	// CanTakeNewRequest() check and the write) surfaces as these. Both are
	// returned during h2's conn-reservation phase, BEFORE any request byte hits
	// the wire, so replaying on a freshly-dialed conn is always safe — exactly
	// what the stdlib http2.Transport does internally via shouldRetryRequest.
	// Our custom uTLS transport (utlsTransport.RoundTrip) drives
	// ClientConn.RoundTrip directly and loses that automatic redial, so we
	// recover it here. Complements the ReadIdleTimeout PING health-check, which
	// cannot cover the race window between a tunnel dying and the next probe.
	"http2: client conn not usable",
	"http2: no cached connection",
	// The same pooled-conn death, but observed from the other side of the race:
	// the ClientConn was handed out and the request written, then the underlying
	// TCP/SOCKS5 tunnel died before the response arrived. h2 fails every in-flight
	// stream on that conn with this. It is a transport flap, not a credential
	// problem — and because a single dead conn kills every request riding it at
	// once, treating it as a credential failure lands several MarkFailure calls in
	// the same second, which is exactly what drives an otherwise-healthy account
	// past the degraded threshold and takes the whole pool dark.
	"http2: client connection lost",
}

// IsTransientNetErr reports whether err looks like a transient wire-level
// failure worth retrying on the same upstream credential, as opposed to a hard
// credential/auth problem (handled via the pool's ReportUpstreamError path) or
// a client disconnect. These are the symptoms of CF edge new-connection
// rate-limiting (RST mid-TLS handshake), a SOCKS5 proxy hiccup, a stale pooled
// h2 connection racing a server-side close, or an h2 stream the server refused.
// None of them mean the credential itself is bad.
func IsTransientNetErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || errors.Is(err, io.EOF) {
		return true
	}
	s := err.Error()
	for _, frag := range transientErrFragments {
		if strings.Contains(s, frag) {
			return true
		}
	}
	return false
}

// retryRoundTripper wraps a base RoundTripper and replays transient wire-level
// failures (see IsTransientNetErr) with exponential backoff + jitter.
//
// Retry is deliberately conservative:
//   - Only when the error arrives BEFORE any response. Once the base RoundTrip
//     returns a *http.Response (even a streaming one), it is handed to the
//     caller untouched — we never retry mid-stream.
//   - Only when the request is replayable: no body, or GetBody is set so the
//     body can be rewound. http.NewRequest* sets GetBody automatically for the
//     bytes.Reader / strings.Reader / bytes.Buffer bodies every forward path
//     here uses; a raw streaming body (GetBody == nil) is never retried.
//   - Context cancellation (the client gave up) ends the loop at once.
type retryRoundTripper struct {
	base http.RoundTripper
}

func (r *retryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.base.RoundTrip(req)
	if err == nil || !replayableRequest(req) {
		return resp, err
	}
	for attempt := 0; err != nil && attempt < len(transientRetryBackoffs); attempt++ {
		if req.Context().Err() != nil || !IsTransientNetErr(err) {
			break
		}
		// Backoff with ±25% jitter so concurrent retries spread out.
		base := transientRetryBackoffs[attempt]
		delay := base - base/4 + time.Duration(rand.Int64N(int64(base/2)+1))
		timer := time.NewTimer(delay)
		select {
		case <-req.Context().Done():
			timer.Stop()
			return resp, err
		case <-timer.C:
		}
		// Rewind the body for the replay. The base RoundTrip consumed (and may
		// have closed) the previous one.
		if req.GetBody != nil {
			body, berr := req.GetBody()
			if berr != nil {
				return resp, err
			}
			req.Body = body
		}
		resp, err = r.base.RoundTrip(req)
	}
	return resp, err
}

// replayableRequest reports whether req can be safely re-sent — either it has no
// body or it carries a GetBody to rewind one.
func replayableRequest(req *http.Request) bool {
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}
