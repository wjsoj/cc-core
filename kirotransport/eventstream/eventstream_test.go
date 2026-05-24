package eventstream

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestCRC32KnownValue(t *testing.T) {
	if got := CRC32([]byte("123456789")); got != 0xCBF43926 {
		t.Fatalf("crc32: got %#x want 0xCBF43926", got)
	}
	if got := CRC32(nil); got != 0 {
		t.Fatalf("crc32 empty: got %#x want 0", got)
	}
}

func TestEncodeDecodeRoundtrip(t *testing.T) {
	h := NewHeaders()
	h.SetString(":message-type", "event")
	h.SetString(":event-type", "assistantResponseEvent")
	h.SetString(":content-type", "application/json")

	payload := []byte(`{"content":"hello"}`)
	frame := EncodeFrame(h, payload)

	got, n, err := ParseFrame(frame)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if n != len(frame) {
		t.Fatalf("consumed %d, want %d", n, len(frame))
	}
	if got.EventType() != "assistantResponseEvent" {
		t.Fatalf("event-type: got %q", got.EventType())
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Fatalf("payload mismatch: got %s", got.Payload)
	}

	var parsed map[string]string
	if err := got.PayloadJSON(&parsed); err != nil {
		t.Fatalf("payload json: %v", err)
	}
	if parsed["content"] != "hello" {
		t.Fatalf("decoded json: %v", parsed)
	}
}

func TestParseFrameIncomplete(t *testing.T) {
	full := EncodeFrame(headersFromMap(map[string]string{":event-type": "x"}), []byte("payload"))
	// truncate one byte at a time, all should return (nil, 0, nil)
	for i := 0; i < len(full); i++ {
		f, n, err := ParseFrame(full[:i])
		if err != nil {
			t.Fatalf("truncate %d: unexpected err %v", i, err)
		}
		if f != nil || n != 0 {
			t.Fatalf("truncate %d: expected incomplete, got frame=%v n=%d", i, f, n)
		}
	}
}

func TestParseFramePreludeCRCMismatch(t *testing.T) {
	full := EncodeFrame(NewHeaders(), []byte("hi"))
	full[8] ^= 0xff // corrupt prelude crc
	_, _, err := ParseFrame(full)
	if err == nil {
		t.Fatal("expected prelude crc error")
	}
	pe, ok := err.(*ParseError)
	if !ok || pe.Stage != "prelude" {
		t.Fatalf("expected ParseError stage=prelude, got %T %v", err, err)
	}
}

func TestParseFrameMessageCRCMismatch(t *testing.T) {
	full := EncodeFrame(NewHeaders(), []byte("hi"))
	full[len(full)-1] ^= 0xff // corrupt message crc
	_, _, err := ParseFrame(full)
	if err == nil {
		t.Fatal("expected message crc error")
	}
	pe, ok := err.(*ParseError)
	if !ok || pe.Stage != "data" {
		t.Fatalf("expected ParseError stage=data, got %T %v", err, err)
	}
}

func TestDecoderStreaming(t *testing.T) {
	f1 := EncodeFrame(headersFromMap(map[string]string{":event-type": "a"}), []byte("alpha"))
	f2 := EncodeFrame(headersFromMap(map[string]string{":event-type": "b"}), []byte("beta"))
	combined := append(f1, f2...)

	dec := NewDecoder()
	// feed in awkward chunks
	chunkSizes := []int{3, 7, 13, 20, 50}
	pos := 0
	var got []*Frame
	for _, sz := range chunkSizes {
		end := pos + sz
		if end > len(combined) {
			end = len(combined)
		}
		if end <= pos {
			break
		}
		if err := dec.Feed(combined[pos:end]); err != nil {
			t.Fatalf("feed: %v", err)
		}
		pos = end
		for {
			f, ok, err := dec.Next()
			if err != nil {
				t.Fatalf("next: %v", err)
			}
			if !ok {
				break
			}
			got = append(got, f)
		}
	}
	if pos < len(combined) {
		if err := dec.Feed(combined[pos:]); err != nil {
			t.Fatalf("feed tail: %v", err)
		}
		for {
			f, ok, err := dec.Next()
			if err != nil {
				t.Fatalf("next tail: %v", err)
			}
			if !ok {
				break
			}
			got = append(got, f)
		}
	}

	if len(got) != 2 {
		t.Fatalf("got %d frames, want 2", len(got))
	}
	if got[0].EventType() != "a" || got[1].EventType() != "b" {
		t.Fatalf("event types: %q %q", got[0].EventType(), got[1].EventType())
	}
}

func TestDecoderSkipFrame(t *testing.T) {
	f1 := EncodeFrame(headersFromMap(map[string]string{":event-type": "ok"}), []byte("ok"))
	bad := EncodeFrame(headersFromMap(map[string]string{":event-type": "bad"}), []byte("data"))
	bad[len(bad)-1] ^= 0xff // corrupt message crc
	f3 := EncodeFrame(headersFromMap(map[string]string{":event-type": "after"}), []byte("after"))

	combined := append(append(f1, bad...), f3...)
	dec := NewDecoder()
	_ = dec.Feed(combined)

	var events []string
	for {
		f, ok, err := dec.Next()
		if err != nil {
			// data error → skip the corrupted frame and continue
			if n := dec.SkipFrame(); n == 0 {
				dec.Skip(1)
			}
			continue
		}
		if !ok {
			break
		}
		events = append(events, f.EventType())
	}
	if len(events) != 2 || events[0] != "ok" || events[1] != "after" {
		t.Fatalf("events: %v", events)
	}
}

func TestHeaderTypes(t *testing.T) {
	h := NewHeaders()
	h.Set("b1", HeaderValue{Type: HeaderBoolTrue, Bool: true})
	h.Set("b0", HeaderValue{Type: HeaderBoolFalse})
	h.Set("byte", HeaderValue{Type: HeaderByte, Int: -3})
	h.Set("short", HeaderValue{Type: HeaderShort, Int: 30000})
	h.Set("int", HeaderValue{Type: HeaderInteger, Int: 1 << 20})
	h.Set("long", HeaderValue{Type: HeaderLong, Int: 1 << 50})
	h.Set("ts", HeaderValue{Type: HeaderTimestamp, Int: 1735_689_600_000})
	h.Set("ba", HeaderValue{Type: HeaderByteArray, Bin: []byte{1, 2, 3}})
	h.Set("str", HeaderValue{Type: HeaderString, Bin: []byte("hi")})
	uuid := make([]byte, 16)
	for i := range uuid {
		uuid[i] = byte(i)
	}
	h.Set("uuid", HeaderValue{Type: HeaderUUID, Bin: uuid})

	frame := EncodeFrame(h, nil)
	parsed, _, err := ParseFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	check := func(name string, want HeaderValue) {
		got, ok := parsed.Headers.Get(name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if got.Type != want.Type {
			t.Fatalf("%s type: got %d want %d", name, got.Type, want.Type)
		}
		if got.Type >= HeaderByte && got.Type <= HeaderLong && got.Int != want.Int {
			t.Fatalf("%s int: got %d want %d", name, got.Int, want.Int)
		}
		if got.Type == HeaderTimestamp && got.Int != want.Int {
			t.Fatalf("%s ts: got %d want %d", name, got.Int, want.Int)
		}
		if (got.Type == HeaderByteArray || got.Type == HeaderString || got.Type == HeaderUUID) && !bytes.Equal(got.Bin, want.Bin) {
			t.Fatalf("%s bin: %v vs %v", name, got.Bin, want.Bin)
		}
	}
	check("b1", HeaderValue{Type: HeaderBoolTrue, Bool: true})
	check("b0", HeaderValue{Type: HeaderBoolFalse})
	check("byte", HeaderValue{Type: HeaderByte, Int: -3})
	check("short", HeaderValue{Type: HeaderShort, Int: 30000})
	check("int", HeaderValue{Type: HeaderInteger, Int: 1 << 20})
	check("long", HeaderValue{Type: HeaderLong, Int: 1 << 50})
	check("ts", HeaderValue{Type: HeaderTimestamp, Int: 1735_689_600_000})
	check("ba", HeaderValue{Type: HeaderByteArray, Bin: []byte{1, 2, 3}})
	check("str", HeaderValue{Type: HeaderString, Bin: []byte("hi")})
	check("uuid", HeaderValue{Type: HeaderUUID, Bin: uuid})
}

func TestBufferOverflow(t *testing.T) {
	dec := NewDecoder()
	dec.SetMaxBuffer(100)
	if err := dec.Feed(make([]byte, 50)); err != nil {
		t.Fatal(err)
	}
	if err := dec.Feed(make([]byte, 60)); err != ErrBufferOverflow {
		t.Fatalf("expected overflow, got %v", err)
	}
}

// helpers
func headersFromMap(m map[string]string) *Headers {
	h := NewHeaders()
	for k, v := range m {
		h.SetString(k, v)
	}
	return h
}

// sanity: ensure JSON payload helpers actually decode something useful
func TestPayloadJSON(t *testing.T) {
	want := map[string]any{"content": "x", "n": float64(7)}
	body, _ := json.Marshal(want)
	frame := EncodeFrame(headersFromMap(map[string]string{":event-type": "test"}), body)
	f, _, err := ParseFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := f.PayloadJSON(&got); err != nil {
		t.Fatal(err)
	}
	if got["content"] != "x" || got["n"] != float64(7) {
		t.Fatalf("got %v", got)
	}
}
