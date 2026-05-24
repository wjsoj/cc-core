package kiroapi

import (
	"io"
	"net/http"

	"github.com/wjsoj/cc-core/kirotransport/eventstream"
)

// Stream is the iterator returned by GenerateAssistantResponse.
//
// Typical use:
//
//	stream, err := client.GenerateAssistantResponse(ctx, req)
//	if err != nil { return err }
//	defer stream.Close()
//	for stream.Next() {
//	    frame := stream.Frame()
//	    et, payload, err := kiroapi.ParseEvent(frame)
//	    if err != nil { return err }
//	    // dispatch on et / payload
//	}
//	if err := stream.Err(); err != nil { return err }
type Stream struct {
	body    io.ReadCloser
	decoder *eventstream.Decoder
	req     http.Header // response headers from the streaming HTTP response

	chunk   [32 * 1024]byte
	current *eventstream.Frame
	lastErr error
	eof     bool
}

// ResponseHeaders returns the HTTP response headers (e.g. x-amzn-requestid).
func (s *Stream) ResponseHeaders() http.Header { return s.req }

// Next advances to the next decoded frame. Returns false on end-of-stream or
// on a non-recoverable error (check Err()).
func (s *Stream) Next() bool {
	for {
		// Try to decode from existing buffered bytes first.
		f, ok, err := s.decoder.Next()
		if err != nil {
			// Try to step past the bad data and retry.
			if n := s.decoder.SkipFrame(); n == 0 {
				s.decoder.Skip(1)
			}
			s.lastErr = err
			return false
		}
		if ok {
			s.current = f
			return true
		}
		// Need more bytes.
		if s.eof {
			return false
		}
		n, err := s.body.Read(s.chunk[:])
		if n > 0 {
			if ferr := s.decoder.Feed(s.chunk[:n]); ferr != nil {
				s.lastErr = ferr
				return false
			}
		}
		if err == io.EOF {
			s.eof = true
			continue // give the decoder one more chance to flush
		}
		if err != nil {
			s.lastErr = err
			return false
		}
	}
}

// Frame returns the frame produced by the most recent Next() == true.
func (s *Stream) Frame() *eventstream.Frame { return s.current }

// Err returns the terminating error, if any. nil on clean EOF.
func (s *Stream) Err() error { return s.lastErr }

// Close releases the underlying HTTP response body.
func (s *Stream) Close() error { return s.body.Close() }
