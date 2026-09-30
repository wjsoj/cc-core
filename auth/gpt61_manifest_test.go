package auth

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestGPT61APIFallbackManifest(t *testing.T) {
	var doc struct {
		Models []struct {
			Slug       string `json:"slug"`
			Context    int    `json:"context_window"`
			MaxContext int    `json:"max_context_window"`
			Default    string `json:"default_reasoning_level"`
			Levels     []struct {
				Effort string `json:"effort"`
			} `json:"supported_reasoning_levels"`
		} `json:"models"`
	}
	if err := json.Unmarshal(SynthesizeCodexModelsManifest([]string{"gpt-6.1-sol"}, "0.159.0"), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Models) != 1 {
		t.Fatalf("new model missing: %+v", doc)
	}
	m := doc.Models[0]
	if m.Slug != "gpt-6.1-sol" || m.Context != 1050000 || m.MaxContext != 1050000 || m.Default != "medium" {
		t.Fatalf("incorrect API metadata: %+v", m)
	}
	var efforts []string
	for _, level := range m.Levels {
		efforts = append(efforts, level.Effort)
	}
	if !reflect.DeepEqual(efforts, []string{"low", "medium", "high", "xhigh", "max"}) {
		t.Fatalf("incorrect reasoning levels: %v", efforts)
	}
}
