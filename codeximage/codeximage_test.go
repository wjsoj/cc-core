package codeximage

import (
	"bytes"
	"encoding/json"
	"errors"
	"mime/multipart"
	"strings"
	"testing"
)

func TestPeek(t *testing.T) {
	if m, st := Peek([]byte(`{"prompt":"x"}`), "application/json"); m != DefaultModel || st {
		t.Fatalf("%q %v", m, st)
	}
	if m, st := Peek([]byte(`{"model":"GPT-Image-1.5","prompt":"x","stream":true}`), "application/json"); m != "gpt-image-1.5" || !st {
		t.Fatalf("%q %v", m, st)
	}
	body, ct := editForm(t, map[string]string{"model": "gpt-image-2.5", "stream": "true", "prompt": "x"})
	if m, st := Peek(body, ct); m != "gpt-image-2.5" || !st {
		t.Fatalf("multipart: %q %v", m, st)
	}
}

func TestIsModelAndPath(t *testing.T) {
	if !IsModel("gpt-image-2") || !IsModel(" GPT-IMAGE-1.5 ") || IsModel("gpt-5.6-sol") || IsModel("dall-e-3") {
		t.Fatal("IsModel")
	}
	if !IsPath(GenerationsPath) || !IsPath(EditsPath) || IsPath("/v1/responses") {
		t.Fatal("IsPath")
	}
	if BackendPath(EditsPath) != "/images/edits" {
		t.Fatal(BackendPath(EditsPath))
	}
}

func editForm(t *testing.T, fields map[string]string, files ...[2]string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	for _, f := range files {
		fw, _ := mw.CreateFormFile(f[0], "f.png")
		_, _ = fw.Write([]byte(f[1]))
	}
	_ = mw.Close()
	return buf.Bytes(), mw.FormDataContentType()
}

func TestUpstreamBodyJSON(t *testing.T) {
	out, err := UpstreamBody([]byte(`{"prompt":"a cube","model":"whatever","stream":true,"size":"1024x1024"}`), "application/json", "gpt-image-2")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	_ = json.Unmarshal(out, &v)
	if v["model"] != "gpt-image-2" || v["size"] != "1024x1024" || v["prompt"] != "a cube" {
		t.Fatalf("%v", v)
	}
	if _, ok := v["stream"]; ok {
		t.Fatal("stream kept")
	}
}

func TestUpstreamBodyMultipartEdit(t *testing.T) {
	png := "\x89PNG\r\n\x1a\n0000"
	body, ct := editForm(t, map[string]string{"prompt": "make it blue", "n": "2", "size": "auto"},
		[2]string{"image[]", png}, [2]string{"image[]", png}, [2]string{"mask", png})
	out, err := UpstreamBody(body, ct, "gpt-image-2")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Model  string `json:"model"`
		Prompt string `json:"prompt"`
		N      int    `json:"n"`
		Size   string `json:"size"`
		Images []struct {
			ImageURL string `json:"image_url"`
		} `json:"images"`
		Mask struct {
			ImageURL string `json:"image_url"`
		} `json:"mask"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatal(err)
	}
	if v.Model != "gpt-image-2" || v.Prompt != "make it blue" || v.N != 2 || v.Size != "auto" || len(v.Images) != 2 {
		t.Fatalf("%s", out)
	}
	if !strings.HasPrefix(v.Images[0].ImageURL, "data:image/png;base64,") || !strings.HasPrefix(v.Mask.ImageURL, "data:image/png;base64,") {
		t.Fatalf("data URLs: %s", out)
	}
}

func TestUpstreamBodyRejects(t *testing.T) {
	notImage, ct := editForm(t, map[string]string{"prompt": "x"}, [2]string{"image", "plain text, not an image"})
	for name, tc := range map[string]struct {
		body []byte
		ct   string
	}{
		"missing prompt": {[]byte(`{"prompt":"  "}`), "application/json"},
		"not json":       {[]byte(`nope`), "application/json"},
		"non-image file": {notImage, ct},
	} {
		_, err := UpstreamBody(tc.body, tc.ct, DefaultModel)
		var re RequestError
		if !errors.As(err, &re) || re.Message == "" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestStartsGeneration(t *testing.T) {
	for _, tc := range []struct {
		typ, item string
		want      bool
	}{
		{"response.image_generation_call.in_progress", "", true},
		{"response.image_generation_call.generating", "", true},
		{"response.image_generation_call.partial_image", "", true},
		{"response.output_item.added", `{"type":"image_generation_call","id":"ig_1"}`, true},
		{"response.output_item.added", `{"type":"message"}`, false},
		{"response.output_text.delta", "", false},
		{"response.created", "", false},
	} {
		if got := StartsGeneration(tc.typ, json.RawMessage(tc.item)); got != tc.want {
			t.Errorf("%s %s: got %v", tc.typ, tc.item, got)
		}
	}
}
