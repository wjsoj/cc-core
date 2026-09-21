package codexoauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// OutputAccumulator restores terminal output when the Codex backend only
// includes it in output_item.done events. It is per response, not per session.
// This matches CLIProxyAPI's HTTP and WebSocket terminal-output reconstruction.
type OutputAccumulator struct {
	indexed  map[int64]json.RawMessage
	fallback []json.RawMessage
}

func (a *OutputAccumulator) Add(index *int64, item json.RawMessage) {
	trimmed := bytes.TrimSpace(item)
	if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
		return
	}
	copyItem := append(json.RawMessage(nil), item...)
	if index == nil {
		a.fallback = append(a.fallback, copyItem)
		return
	}
	if a.indexed == nil {
		a.indexed = make(map[int64]json.RawMessage)
	}
	a.indexed[*index] = copyItem
}

func (a *OutputAccumulator) Patch(response []byte) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(response, &obj); err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, fmt.Errorf("terminal response must be an object")
	}
	var output []json.RawMessage
	_ = json.Unmarshal(obj["output"], &output)
	changed := false
	if len(output) == 0 && (len(a.indexed) > 0 || len(a.fallback) > 0) {
		indexes := make([]int64, 0, len(a.indexed))
		for index := range a.indexed {
			indexes = append(indexes, index)
		}
		sort.Slice(indexes, func(i, j int) bool { return indexes[i] < indexes[j] })
		for _, index := range indexes {
			output = append(output, a.indexed[index])
		}
		output = append(output, a.fallback...)
		changed = true
	} else {
		// The terminal event can include output but omit the ids needed for a
		// subsequent agent turn. Hydrate only absent ids, never overwrite one.
		for i, item := range output {
			var current, done map[string]json.RawMessage
			if json.Unmarshal(item, &current) != nil || current == nil {
				continue
			}
			var id string
			if raw := current["id"]; len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
				if json.Unmarshal(raw, &id) != nil || id != "" {
					continue
				}
			}
			if json.Unmarshal(a.indexed[int64(i)], &done) != nil {
				continue
			}
			if json.Unmarshal(done["id"], &id) != nil || id == "" {
				continue
			}
			// Don't attach an id from an unrelated output item.
			if !bytes.Equal(current["type"], done["type"]) {
				continue
			}
			current["id"] = done["id"]
			patched, err := json.Marshal(current)
			if err != nil {
				return nil, err
			}
			output[i] = patched
			changed = true
		}
	}
	if !changed {
		return response, nil
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		return nil, err
	}
	obj["output"] = encoded
	return json.Marshal(obj)
}

// Observe returns unchanged bytes except for terminal events requiring repair.
func (a *OutputAccumulator) Observe(payload []byte) []byte {
	var event struct {
		Type     string          `json:"type"`
		Index    *int64          `json:"output_index"`
		Item     json.RawMessage `json:"item"`
		Response json.RawMessage `json:"response"`
	}
	if json.Unmarshal(payload, &event) != nil {
		return payload
	}
	switch event.Type {
	case "response.output_item.done":
		a.Add(event.Index, event.Item)
	case "response.completed", "response.incomplete":
		patched, err := a.Patch(event.Response)
		if err != nil || bytes.Equal(patched, event.Response) {
			return payload
		}
		var envelope map[string]json.RawMessage
		if json.Unmarshal(payload, &envelope) != nil {
			return payload
		}
		envelope["response"] = patched
		if out, err := json.Marshal(envelope); err == nil {
			return out
		}
	}
	return payload
}
