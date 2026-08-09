package mimicry

import (
	"bytes"
	"encoding/json"
	"errors"
)

// cache_control repair for genuine Claude Code requests that reached us over a
// custom base URL.
//
// Real Claude Code puts breakpoints on the same two system blocks either way —
// the last two — but the values differ, because ttl and scope each require a
// beta the custom-base-url client could not declare
// (crack/thirdparty/SPEC.md §2c):
//
//	OAuth main   [-, -, {ephemeral,1h,global}, {ephemeral,1h}]
//	custom main  [-,    {ephemeral},           {ephemeral}   ]
//
// So the repair restores ttl/scope on breakpoints that already exist. It never
// adds a breakpoint and never removes one: block *count* differs between the two
// captures for a content reason (the OAuth session had an extra appended system
// section), not a mode reason, and the captured title request has no breakpoints
// on either path.
//
// Only legal once beta.go has put extended-cache-ttl-2025-04-11 back in the
// header, which is why the two ship together. Worth real money as well as
// fingerprint: without it every forwarded request writes a 5-minute cache entry
// where the real client writes a 1-hour global one.

// claudeCacheControl marshals in the field order the real client emits —
// {"type","ttl","scope"}. A map would sort the keys alphabetically and produce
// {"scope","ttl","type"}, which no capture shows.
type claudeCacheControl struct {
	Type  string `json:"type"`
	TTL   string `json:"ttl,omitempty"`
	Scope string `json:"scope,omitempty"`
}

func claudeSystemCacheControl(withGlobalScope bool) claudeCacheControl {
	cc := claudeCacheControl{Type: "ephemeral", TTL: ClaudeDefaultCacheTTL}
	if withGlobalScope {
		cc.Scope = ClaudeDefaultCacheScope
	}
	return cc
}

// isBareEphemeral reports whether raw is exactly {"type":"ephemeral"} — the
// shape a custom-base-url client emits when it cannot declare the ttl/scope
// betas. Anything else is left alone: a client that asked for a specific ttl
// made a deliberate choice, and overriding it would be a functional change
// dressed up as a fingerprint fix.
func isBareEphemeral(raw json.RawMessage) bool {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || len(obj) != 1 {
		return false
	}
	var kind string
	if err := json.Unmarshal(obj["type"], &kind); err != nil {
		return false
	}
	return kind == "ephemeral"
}

// systemCacheControlReplacements returns the byte edits that upgrade the bare
// breakpoints on the last two system blocks. Offsets are absolute in body.
//
// Returning no replacements is the normal outcome for a first-party request and
// for any request whose breakpoints are already correct; it is never an error.
func systemCacheControlReplacements(body []byte, systemSpan jsonValueSpan) ([]byteReplacement, error) {
	rawSystem := body[systemSpan.start:systemSpan.end]
	blocks, err := jsonArrayElementSpans(rawSystem)
	if err != nil {
		return nil, err
	}

	out := make([]byteReplacement, 0, 2)
	for offset := 2; offset >= 1; offset-- {
		index := len(blocks) - offset
		if index < 0 {
			continue
		}
		blockSpan := blocks[index]
		block := rawSystem[blockSpan.start:blockSpan.end]
		valueSpan, ok := findJSONObjectMemberSpan(block, "cache_control")
		if !ok {
			continue
		}
		if !isBareEphemeral(block[valueSpan.start:valueSpan.end]) {
			continue
		}
		encoded, err := json.Marshal(claudeSystemCacheControl(offset == 2))
		if err != nil {
			return nil, err
		}
		base := systemSpan.start + blockSpan.start
		out = append(out, byteReplacement{
			start: base + valueSpan.start,
			end:   base + valueSpan.end,
			value: encoded,
		})
	}
	return out, nil
}

// setJSONObjectMember sets name=value on a JSON object without disturbing the
// bytes of anything else.
//
// The obvious implementation — unmarshal into a map, marshal it back — silently
// reorders every key alphabetically, so a captured block
// {"type","text","cache_control"} comes back out as
// {"cache_control","text","type"}. Key order is part of the wire shape we are
// trying to reproduce, so edit in place instead: replace an existing member's
// value where it sits, or append a new one last, which is where the real client
// carries cache_control.
func setJSONObjectMember(raw json.RawMessage, name string, value any) (json.RawMessage, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if span, ok := findJSONObjectMemberSpan(raw, name); ok {
		return applyByteReplacements(raw, []byteReplacement{
			{start: span.start, end: span.end, value: encoded},
		})
	}

	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return nil, errors.New("value is not a JSON object")
	}
	key, err := json.Marshal(name)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(trimmed)+len(key)+len(encoded)+2)
	out = append(out, trimmed[:len(trimmed)-1]...)
	// An empty object has no preceding member to separate from.
	if len(bytes.TrimSpace(trimmed[1:len(trimmed)-1])) > 0 {
		out = append(out, ',')
	}
	out = append(out, key...)
	out = append(out, ':')
	out = append(out, encoded...)
	out = append(out, '}')
	if !json.Valid(out) {
		return nil, errors.New("setting JSON object member produced invalid JSON")
	}
	return out, nil
}

// deleteJSONObjectMember removes name from a JSON object, again without
// reordering what stays. Returns the input unchanged when the member is absent.
func deleteJSONObjectMember(raw json.RawMessage, name string) (json.RawMessage, error) {
	span, ok := findJSONObjectMemberSpan(raw, name)
	if !ok {
		return raw, nil
	}
	// Widen the span to swallow the key, its colon, and one adjacent comma so
	// the result stays well-formed whether the member was first, middle, or last.
	// Walk back over the exact grammar rather than guessing: value ← ws ← ':'
	// ← ws ← closing quote ← key ← opening quote.
	cursor := skipJSONSpaceBackward(raw, span.start)
	if cursor == 0 || raw[cursor-1] != ':' {
		return nil, errors.New("member value is not preceded by a colon")
	}
	cursor = skipJSONSpaceBackward(raw, cursor-1)
	if cursor == 0 || raw[cursor-1] != '"' {
		return nil, errors.New("member key is not a quoted string")
	}
	start := bytes.LastIndexByte(raw[:cursor-1], '"')
	if start < 0 {
		return nil, errors.New("could not locate the member key")
	}

	end := span.end
	for end < len(raw) && isJSONSpace(raw[end]) {
		end++
	}
	// Drop exactly one separator: the following comma when there is one, else
	// the preceding one. Whitespace can sit on either side of both.
	if end < len(raw) && raw[end] == ',' {
		end++
	} else if before := skipJSONSpaceBackward(raw, start); before > 0 && raw[before-1] == ',' {
		start = before - 1
	}
	out, err := applyByteReplacements(raw, []byteReplacement{{start: start, end: end}})
	if err != nil {
		return nil, err
	}
	if !json.Valid(out) {
		return nil, errors.New("deleting JSON object member produced invalid JSON")
	}
	return out, nil
}

func isJSONSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

// skipJSONSpaceBackward returns the smallest index <= at with no insignificant
// whitespace immediately before it.
func skipJSONSpaceBackward(data []byte, at int) int {
	for at > 0 && isJSONSpace(data[at-1]) {
		at--
	}
	return at
}

// jsonArrayElementSpans returns the span of every element of a JSON array.
func jsonArrayElementSpans(data []byte) ([]jsonValueSpan, error) {
	if !json.Valid(data) {
		return nil, errors.New("value is not valid JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	opening, err := dec.Token()
	if err != nil || opening != json.Delim('[') {
		return nil, errors.New("value is not a JSON array")
	}
	var spans []jsonValueSpan
	for dec.More() {
		span, spanErr := decodeRawValueSpan(dec, data)
		if spanErr != nil {
			return nil, spanErr
		}
		spans = append(spans, span)
	}
	if _, err = dec.Token(); err != nil {
		return nil, err
	}
	return spans, nil
}

// findJSONObjectMemberSpan is the absent-is-fine counterpart to
// requireJSONObjectMemberSpan. A duplicate key reports not-found: rewriting one
// of two same-named members would be arbitrary.
func findJSONObjectMemberSpan(data []byte, name string) (jsonValueSpan, bool) {
	if !json.Valid(data) {
		return jsonValueSpan{}, false
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	opening, err := dec.Token()
	if err != nil || opening != json.Delim('{') {
		return jsonValueSpan{}, false
	}
	var found jsonValueSpan
	count := 0
	for dec.More() {
		keyToken, tokenErr := dec.Token()
		if tokenErr != nil {
			return jsonValueSpan{}, false
		}
		key, ok := keyToken.(string)
		if !ok {
			return jsonValueSpan{}, false
		}
		span, spanErr := decodeRawValueSpan(dec, data)
		if spanErr != nil {
			return jsonValueSpan{}, false
		}
		if key == name {
			count++
			found = span
		}
	}
	if count != 1 {
		return jsonValueSpan{}, false
	}
	return found, true
}
