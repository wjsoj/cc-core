package servicetier

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestNormalizeRequest(t *testing.T) {
	for _, tc := range []struct{ body, want, tier string }{
		{`{ "model":"m", "service_tier" : " FAST ","input":{"service_tier":"fast"}}`, `{ "model":"m", "service_tier" : "priority","input":{"service_tier":"fast"}}`, "priority"},
		{`{"service_tier":"priority","z":1,"a":2}`, `{"service_tier":"priority","z":1,"a":2}`, "priority"},
		{`{"service_tier":"bogus","model":"m"}`, `{"model":"m"}`, ""},
		{`{"model":"m","service_tier":null,"input":[]}`, `{"model":"m","input":[]}`, ""},
		{`{"model":"m","service_tier":""}`, `{"model":"m"}`, ""},
		{`{"service_tier":null}`, `{}`, ""},
		{`{"service_tier":" FLEX "}`, `{"service_tier":"flex"}`, "flex"},
		{`{"model":"m"}`, `{"model":"m"}`, ""},
	} {
		t.Run(tc.body, func(t *testing.T) {
			got, tier, err := NormalizeRequest([]byte(tc.body))
			if err != nil || string(got) != tc.want || tier != tc.tier {
				t.Fatalf("got %s / %q / %v, want %s / %q", got, tier, err, tc.want, tc.tier)
			}
		})
	}
	for _, body := range []string{`[]`, `{"service_tier":1}`, `{"service_tier":true}`, `{"service_tier":"priority","service_tier":"default"}`, `{"service_tier":"fast","service_\u0074ier":"default"}`, `{"service_tier":"fast"} {}`, `{"service_tier":"fast"`} {
		if _, _, err := NormalizeRequest([]byte(body)); err == nil {
			t.Errorf("accepted invalid %s", body)
		}
	}
}

func TestResolveOpenAI(t *testing.T) {
	for _, tc := range []struct {
		requested, observed string
		oauth               bool
		want                string
		down                bool
	}{
		{"fast", "default", true, "priority", false}, {"fast", "default", false, "default", true},
		{"priority", "flex", true, "flex", true}, {"priority", "", false, "priority", false},
		{"priority", "new-tier", false, "priority", false}, {"", "priority", false, "", false},
		{"default", "flex", false, "flex", true}, {"flex", "priority", false, "flex", false},
		{"auto", "priority", true, "auto", false},
	} {
		got := ResolveOpenAI(tc.requested, tc.observed, tc.oauth)
		if got.Billing != tc.want || got.Downgraded != tc.down {
			t.Errorf("%+v => %+v", tc, got)
		}
	}
}

// One byte per Read exercises split field names, CRLF, and the terminal line
// without a trailing event delimiter. The relay must receive identical bytes.
type oneByteReader struct{ io.Reader }

func (r oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}
func TestBodyObserver(t *testing.T) {
	for _, body := range []string{
		` {"service_tier":"default","output":[]}`,
		"event: response.created\r\ndata: {\"response\":{\"service_tier\":\"priority\"}}\r\n\r\ndata: {\"response\":{\"service_tier\":\"default\"}}",
		"data: {\"response\":{\n" + "data: \"service_tier\":\"default\"}}\n\n",
	} {
		observed := ObserveBody(io.NopCloser(oneByteReader{strings.NewReader(body)}))
		got, err := io.ReadAll(observed)
		if err != nil {
			t.Fatal(err)
		}
		_ = observed.Close()
		if string(got) != body || observed.Observed() != "default" {
			t.Fatalf("body %q -> %q tier %q", body, got, observed.Observed())
		}
	}
}
func TestBodyObserverOversizeAndRecovery(t *testing.T) {
	body := "data: " + strings.Repeat("x", maxObservationBytes) + "\n\ndata: {\"service_tier\":\"flex\"}\n\n"
	observer := ObserveBody(io.NopCloser(strings.NewReader(body)))
	if _, err := io.Copy(io.Discard, observer); err != nil {
		t.Fatal(err)
	}
	if observer.Observed() != "flex" {
		t.Fatal(observer.Observed())
	}
	if cap(observer.buffer) > maxObservationBytes*2 || cap(observer.event) > maxObservationBytes*2 {
		t.Fatal("unbounded observation")
	}
}
func TestBodyObserverCloseBeforeEOF(t *testing.T) {
	raw := []byte(`{"service_tier":"priority"}`)
	b := ObserveBody(io.NopCloser(bytes.NewReader(raw)))
	if _, err := io.ReadFull(b, make([]byte, len(raw))); err != nil {
		t.Fatal(err)
	}
	_ = b.Close()
	if b.Observed() != "priority" {
		t.Fatal(b.Observed())
	}
}
func TestTurnTrackerResetsTierAndFreezesQueue(t *testing.T) {
	tr := &TurnTracker{}
	if !tr.Sent([]byte(`{"type":"response.create","model":"gpt-5.5","service_tier":"fast"}`)) || !tr.Sent([]byte(`{"type":"response.create","model":"gpt-6-astra"}`)) {
		t.Fatal("queue rejected")
	}
	tr.Observe([]byte(`{"type":"response.completed","response":{"service_tier":"default"}}`))
	tr.Complete()
	first := tr.LastCompleted()
	tr.Complete()
	second := tr.LastCompleted()
	if first != (Turn{Model: "gpt-5.5", Requested: "priority", Observed: "default"}) || second != (Turn{Model: "gpt-6-astra"}) {
		t.Fatalf("first %+v second %+v", first, second)
	}
}
