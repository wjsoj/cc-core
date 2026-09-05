package servicetier

import (
	"bytes"
	"io"
)

const maxObservationBytes = 16 << 20

// BodyObserver passes bytes through unchanged while observing JSON or SSE
// service tiers, before a caller transforms/scrubs the response. It does not
// read ahead or delay streaming. Oversized records are skipped, never buffered
// without a bound. Only the response reader goroutine may use it.
type BodyObserver struct {
	io.ReadCloser
	buffer   []byte
	event    []byte
	mode     byte
	dropping bool
	tier     string
}

func ObserveBody(body io.ReadCloser) *BodyObserver { return &BodyObserver{ReadCloser: body} }

func (b *BodyObserver) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.feed(p[:n])
	if err != nil {
		b.flush()
	}
	return n, err
}

func (b *BodyObserver) Close() error {
	b.flush()
	return b.ReadCloser.Close()
}

func (b *BodyObserver) Observed() string { return b.tier }

func (b *BodyObserver) feed(p []byte) {
	if b.mode == 0 {
		trimmed := bytes.TrimSpace(p)
		if len(trimmed) == 0 {
			return
		}
		b.mode = 's'
		if trimmed[0] == '{' {
			b.mode = 'j'
		}
	}
	if b.mode == 'j' {
		if !b.dropping && len(b.buffer)+len(p) <= maxObservationBytes {
			b.buffer = append(b.buffer, p...)
		} else {
			b.buffer = nil
			b.dropping = true
		}
		return
	}
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		n := len(p)
		if i >= 0 {
			n = i
		}
		if !b.dropping && len(b.buffer)+n <= maxObservationBytes {
			b.buffer = append(b.buffer, p[:n]...)
		} else {
			b.buffer = nil
			b.dropping = true
		}
		if i < 0 {
			return
		}
		if !b.dropping {
			b.line(b.buffer)
		} else {
			b.event = nil
		}
		b.buffer = b.buffer[:0]
		b.dropping = false
		p = p[i+1:]
	}
}

func (b *BodyObserver) line(line []byte) {
	line = bytes.TrimSuffix(line, []byte{'\r'})
	if len(line) == 0 {
		b.observe(b.event)
		b.event = b.event[:0]
		return
	}
	if data, ok := bytes.CutPrefix(line, []byte("data:")); ok {
		data = bytes.TrimPrefix(data, []byte{' '})
		// Single-line events can be observed immediately, even when a relay
		// stops reading on the terminal line before the trailing blank line.
		b.observe(data)
		if len(b.event)+len(data)+1 <= maxObservationBytes {
			b.event = append(b.event, data...)
			b.event = append(b.event, '\n')
		} else {
			b.event = nil
		}
	}
}

func (b *BodyObserver) observe(data []byte) {
	if tier := Response(data); tier != "" {
		b.tier = tier
	}
}

func (b *BodyObserver) flush() {
	if b.mode == 'j' {
		if !b.dropping {
			b.observe(b.buffer)
		}
	} else {
		if !b.dropping && len(b.buffer) > 0 {
			b.line(b.buffer)
		}
		b.observe(b.event)
	}
	b.buffer, b.event = nil, nil
}
