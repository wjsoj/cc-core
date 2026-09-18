// Package codeximage serves the OpenAI Images API (/v1/images/generations,
// /v1/images/edits) on a ChatGPT subscription credential, and recognises image
// generation inside a Codex Responses turn.
//
// The ChatGPT Codex backend serves the Images API natively at
// {backend}/codex/images/{generations,edits}: same request fields, same
// response shape, `usage` included. Both sibling relays (sub2api, CLIProxyAPI)
// call it directly for gpt-image-*, and a production probe on 2026-09-18
// returned a normal 200 with b64_json and usage after 25s. So relaying is a
// pass-through; the one rewrite is a multipart edit, which the backend takes
// as JSON with the uploaded files inlined as data URLs.
//
// Everything here is framework-free. Pool selection, billing and logging stay
// with the caller; usage.ParseImagesAPIUsage reads the response's usage and
// pricing prices it at the image card.
package codeximage

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	GenerationsPath = "/v1/images/generations"
	EditsPath       = "/v1/images/edits"
	DefaultModel    = "gpt-image-2"

	// MaxRequestBytes bounds an images request, multipart uploads included.
	MaxRequestBytes = 64 << 20
	// MaxResponseBytes bounds a backend reply; one 2K PNG is ~5MB of base64.
	MaxResponseBytes = 128 << 20
)

// CommitAfter is how long an Images API request may wait on the backend
// before the caller commits a 200 and starts stream.JSONKeepalive. Refusals
// (quota, auth, capacity) arrive well inside it and can still fail over
// invisibly; a generation merely working past it keeps a live connection
// instead of dying at the client's 60s idle timeout. Measured: a low-quality
// 1024² image took 18s to its first byte. A var so tests can shorten it.
var CommitAfter = 15 * time.Second

var models = map[string]bool{
	"gpt-image-1.5":          true,
	"gpt-image-2":            true,
	"gpt-image-2.5":          true,
	"gpt-image-2.5-flare":    true,
	"gpt-image-2.5-sunburst": true,
}

// IsModel reports whether the backend's Images API serves model.
func IsModel(model string) bool { return models[strings.ToLower(strings.TrimSpace(model))] }

// IsPath reports whether a client path is one of the Images API routes.
func IsPath(path string) bool { return path == GenerationsPath || path == EditsPath }

// BackendPath maps a client path to its route under {backend}/codex.
func BackendPath(path string) string { return strings.TrimPrefix(path, "/v1") }

// RequestError is a client-side fault in an images request; Error is safe to
// show the client.
type RequestError struct{ Message string }

func (e RequestError) Error() string { return e.Message }

// Peek reads the model and stream flag from either request shape. An absent
// model is DefaultModel, as in both sibling relays. The model is lowercased.
func Peek(body []byte, contentType string) (model string, stream bool) {
	if form, ok := parseMultipart(body, contentType); ok {
		defer func() { _ = form.RemoveAll() }()
		model = strings.TrimSpace(firstValue(form, "model"))
		stream, _ = strconv.ParseBool(strings.TrimSpace(firstValue(form, "stream")))
	} else {
		var peek struct {
			Model  string `json:"model"`
			Stream bool   `json:"stream"`
		}
		_ = json.Unmarshal(body, &peek)
		model, stream = strings.TrimSpace(peek.Model), peek.Stream
	}
	if model == "" {
		model = DefaultModel
	}
	return strings.ToLower(model), stream
}

// UpstreamBody renders a client request as the JSON the backend takes: model
// pinned to the caller's validated name, `stream` removed (the relay is
// non-streaming), multipart files inlined as data URLs. Errors are
// RequestError.
func UpstreamBody(body []byte, contentType, model string) ([]byte, error) {
	var out map[string]any
	if form, ok := parseMultipart(body, contentType); ok {
		defer func() { _ = form.RemoveAll() }()
		var err error
		if out, err = formToJSON(form); err != nil {
			return nil, err
		}
	} else if err := json.Unmarshal(body, &out); err != nil || out == nil {
		return nil, RequestError{"The request body must be JSON or multipart/form-data."}
	}
	if p, _ := out["prompt"].(string); strings.TrimSpace(p) == "" {
		return nil, RequestError{"`prompt` is required."}
	}
	out["model"] = model
	delete(out, "stream")
	return json.Marshal(out)
}

func parseMultipart(body []byte, contentType string) (*multipart.Form, bool) {
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.HasPrefix(strings.ToLower(mt), "multipart/") || params["boundary"] == "" {
		return nil, false
	}
	form, err := multipart.NewReader(bytes.NewReader(body), params["boundary"]).ReadForm(MaxRequestBytes)
	if err != nil {
		return nil, false
	}
	return form, true
}

func firstValue(form *multipart.Form, key string) string {
	if v := form.Value[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// formToJSON follows CLIProxyAPI's multipart rewrite: scalar fields copied
// (n, output_compression, partial_images as integers), image / image[] files as
// images[].image_url, the mask file or mask[...] fields as mask.
func formToJSON(form *multipart.Form) (map[string]any, error) {
	out := map[string]any{}
	for key, values := range form.Value {
		key = strings.TrimSpace(key)
		if key == "" || key == "model" || key == "stream" || len(values) == 0 {
			continue
		}
		switch key {
		case "mask[image_url]":
			out["mask"] = map[string]any{"image_url": values[0]}
			continue
		case "mask[file_id]":
			out["mask"] = map[string]any{"file_id": values[0]}
			continue
		}
		conv := func(v string) any {
			v = strings.TrimSpace(v)
			switch key {
			case "n", "output_compression", "partial_images":
				if n, err := strconv.ParseInt(v, 10, 64); err == nil {
					return n
				}
			}
			return v
		}
		if len(values) == 1 {
			out[key] = conv(values[0])
			continue
		}
		list := make([]any, 0, len(values))
		for _, v := range values {
			list = append(list, conv(v))
		}
		out[key] = list
	}
	var images []any
	for _, key := range []string{"image", "image[]"} {
		for _, fh := range form.File[key] {
			url, err := fileDataURL(fh)
			if err != nil {
				return nil, err
			}
			images = append(images, map[string]any{"image_url": url})
		}
	}
	if len(images) > 0 {
		out["images"] = images
	}
	if masks := form.File["mask"]; len(masks) > 0 {
		url, err := fileDataURL(masks[0])
		if err != nil {
			return nil, err
		}
		out["mask"] = map[string]any{"image_url": url}
	}
	return out, nil
}

func fileDataURL(fh *multipart.FileHeader) (string, error) {
	f, err := fh.Open()
	if err != nil {
		return "", RequestError{"An uploaded image could not be read."}
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(f)
	if err != nil || len(raw) == 0 {
		return "", RequestError{"An uploaded image could not be read."}
	}
	ct := fh.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "image/") {
		ct = http.DetectContentType(raw)
	}
	if !strings.HasPrefix(ct, "image/") {
		return "", RequestError{"Uploaded files must be images (PNG, JPEG or WebP)."}
	}
	return "data:" + ct + ";base64," + base64.StdEncoding.EncodeToString(raw), nil
}

// StartsGeneration reports whether a Responses event shows the turn has begun
// generating an image: any response.image_generation_call.* event, or an
// output item of that type being opened. From here the turn will be silent for
// the length of the generation — the cue for a non-streaming relay to start
// its keepalive.
func StartsGeneration(eventType string, item json.RawMessage) bool {
	if strings.HasPrefix(eventType, "response.image_generation_call.") {
		return true
	}
	if eventType != "response.output_item.added" || len(item) == 0 {
		return false
	}
	var it struct {
		Type string `json:"type"`
	}
	return json.Unmarshal(item, &it) == nil && it.Type == "image_generation_call"
}
