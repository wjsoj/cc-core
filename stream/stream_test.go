package stream

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
)

// Decompress tests

func TestDecompressGzip(t *testing.T) {
	want := "hello world"
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write([]byte(want))
	gw.Close()

	resp := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(&buf),
	}
	resp.Header.Set("Content-Encoding", "gzip")
	resp.Header.Set("Content-Length", "999")

	Decompress(resp)

	got, _ := io.ReadAll(resp.Body)
	if string(got) != want {
		t.Fatalf("got=%q want=%q", got, want)
	}
	if resp.Header.Get("Content-Encoding") != "" {
		t.Fatal("Content-Encoding should be stripped")
	}
	if resp.Header.Get("Content-Length") != "" {
		t.Fatal("Content-Length should be stripped")
	}
}

func TestDecompressBrotli(t *testing.T) {
	want := "hello brotli world"
	var buf bytes.Buffer
	bw := brotli.NewWriter(&buf)
	bw.Write([]byte(want))
	bw.Close()

	resp := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(&buf),
	}
	resp.Header.Set("Content-Encoding", "br")

	Decompress(resp)

	got, _ := io.ReadAll(resp.Body)
	if string(got) != want {
		t.Fatalf("got=%q want=%q", got, want)
	}
}

func TestDecompressIdentityNoOp(t *testing.T) {
	body := "plain text"
	resp := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(strings.NewReader(body)),
	}
	resp.Header.Set("Content-Encoding", "identity")
	resp.Header.Set("Content-Length", "10")
	Decompress(resp)
	got, _ := io.ReadAll(resp.Body)
	if string(got) != body {
		t.Fatalf("identity should pass through, got %q", got)
	}
	if resp.Header.Get("Content-Length") == "" {
		t.Fatal("identity case should NOT strip Content-Length")
	}
}

func TestDecompressUnknownEncoding(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(strings.NewReader("opaque")),
	}
	resp.Header.Set("Content-Encoding", "zstd")
	Decompress(resp)
	if resp.Header.Get("Content-Encoding") != "zstd" {
		t.Fatal("unknown encoding must pass through unchanged")
	}
}

// SSEScanner tests

func TestSSEScannerBasic(t *testing.T) {
	stream := "event: message_start\ndata: {\"type\":\"start\"}\n\nevent: message_delta\ndata: {\"usage\":{\"input_tokens\":10}}\n\n"
	s := NewSSEScanner(strings.NewReader(stream), 0)

	var events []string
	var datas []string
	for s.Scan() {
		if d := s.Data(); d != nil {
			events = append(events, s.Event())
			datas = append(datas, string(d))
		}
	}
	if s.Err() != nil {
		t.Fatalf("Err: %v", s.Err())
	}

	if len(events) != 2 || events[0] != "message_start" || events[1] != "message_delta" {
		t.Fatalf("events = %v", events)
	}
	if datas[1] != `{"usage":{"input_tokens":10}}` {
		t.Fatalf("data[1] = %q", datas[1])
	}
}

func TestSSEScannerReemitsLinesVerbatim(t *testing.T) {
	stream := "event: ping\ndata: hi\n\n"
	var out bytes.Buffer
	s := NewSSEScanner(strings.NewReader(stream), 0)
	for s.Scan() {
		out.Write(s.Line())
	}
	if out.String() != stream {
		t.Fatalf("re-emit mismatch:\ngot:  %q\nwant: %q", out.String(), stream)
	}
}

func TestSSEScannerLastLineWithoutNewline(t *testing.T) {
	// Truncated stream — last "data:" line lacks the trailing \n
	stream := "event: x\ndata: tail"
	s := NewSSEScanner(strings.NewReader(stream), 0)
	var datas [][]byte
	for s.Scan() {
		if d := s.Data(); d != nil {
			datas = append(datas, append([]byte{}, d...))
		}
	}
	if s.Err() != nil {
		t.Fatalf("Err = %v", s.Err())
	}
	if len(datas) != 1 || string(datas[0]) != "tail" {
		t.Fatalf("got %v", datas)
	}
}
