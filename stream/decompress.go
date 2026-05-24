// Package stream provides framework-agnostic helpers for working with
// upstream HTTP responses that may be gzip/br compressed (Decompress)
// and Server-Sent Events streams (Scanner).
//
// # Why
//
// Reverse-proxies that need to look like a "real" CLI client typically
// advertise `Accept-Encoding: gzip, br` even on streaming endpoints,
// because real clients (e.g. Claude Code) do. But every internal path —
// usage parsing, SSE re-streaming, body rewriting — wants plain bytes.
// Decompress swaps resp.Body for a transparent decoder when applicable
// and strips Content-Encoding / Content-Length so the response forwarded
// downstream is plain text.
package stream

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
)

// Decompress wraps resp.Body with a transparent decompressor when the
// upstream response is `gzip` or `br` encoded, then drops the
// Content-Encoding and Content-Length headers so the response we forward
// downstream looks plain. No-op when the encoding is empty / identity /
// unknown (e.g. zstd, deflate — pass through unchanged).
//
// Safe to call multiple times on the same response: after the first call
// Content-Encoding is gone, so subsequent calls are no-ops.
func Decompress(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	if enc == "" || enc == "identity" {
		return
	}
	switch enc {
	case "gzip":
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			// Bad gzip stream — leave body alone and let the caller fail
			// naturally on read. Don't surface a hard error here; this is
			// best-effort transparency, not validation.
			return
		}
		resp.Body = &decompressedBody{rc: gz, underlying: resp.Body}
	case "br":
		br := brotli.NewReader(resp.Body)
		resp.Body = &decompressedBody{rc: io.NopCloser(br), underlying: resp.Body}
	default:
		// Unknown encoding — pass through unchanged.
		return
	}
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")
}

// decompressedBody chains a decompressor's Close to the underlying body
// so callers that defer resp.Body.Close() don't leak the original socket.
type decompressedBody struct {
	rc         io.ReadCloser
	underlying io.ReadCloser
}

func (d *decompressedBody) Read(p []byte) (int, error) { return d.rc.Read(p) }
func (d *decompressedBody) Close() error {
	_ = d.rc.Close()
	return d.underlying.Close()
}
