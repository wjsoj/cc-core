package usage

import "testing"

func TestParseResponsesImageGenUsage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		want    Counts
	}{
		{"streaming terminal", `{"type":"response.completed","response":{"usage":{"input_tokens":900,"output_tokens":40},"tool_usage":{"image_gen":{"input_tokens":60,"input_tokens_details":{"text_tokens":50,"image_tokens":10},"output_tokens":1056,"total_tokens":1116},"web_search":{"num_requests":0}}}}`,
			Counts{ImageGenTextInputTokens: 50, ImageGenImageInputTokens: 10, ImageGenOutputTokens: 1056}},
		{"non-stream body", `{"object":"response","tool_usage":{"image_gen":{"input_tokens":30,"output_tokens":272}}}`,
			Counts{ImageGenTextInputTokens: 30, ImageGenOutputTokens: 272}},
		{"captured zero block", `{"response":{"tool_usage":{"image_gen":{"input_tokens":0,"input_tokens_details":{"image_tokens":0,"text_tokens":0},"output_tokens":0,"total_tokens":0}}}}`, Counts{}},
		{"no tool usage", `{"type":"response.output_text.delta","delta":"hi"}`, Counts{}},
		{"chat usage is not image usage", `{"usage":{"input_tokens":10,"output_tokens":5}}`, Counts{}},
		{"malformed", `{`, Counts{}},
		{"negative clamps", `{"tool_usage":{"image_gen":{"input_tokens":-5,"output_tokens":-1}}}`, Counts{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseResponsesImageGenUsage([]byte(tc.payload)); got != tc.want {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

func TestParseImagesAPIUsage(t *testing.T) {
	got := ParseImagesAPIUsage([]byte(`{"created":1,"data":[{"b64_json":"x"}],"usage":{"input_tokens":20,"input_tokens_details":{"text_tokens":12,"image_tokens":8},"output_tokens":4160,"total_tokens":4180}}`))
	want := Counts{ImageGenTextInputTokens: 12, ImageGenImageInputTokens: 8, ImageGenOutputTokens: 4160}
	if got != want {
		t.Fatalf("got %+v want %+v", got, want)
	}
	if !got.HasImageGen() || (Counts{}).HasImageGen() {
		t.Fatal("HasImageGen wrong")
	}
}

func TestCountsAddCarriesImageGen(t *testing.T) {
	var c Counts
	c.Add(Counts{ImageGenTextInputTokens: 1, ImageGenImageInputTokens: 2, ImageGenOutputTokens: 3})
	c.Add(Counts{ImageGenOutputTokens: 4})
	if c.ImageGenTextInputTokens != 1 || c.ImageGenImageInputTokens != 2 || c.ImageGenOutputTokens != 7 {
		t.Fatalf("%+v", c)
	}
}

func TestWithResponsesImageGen(t *testing.T) {
	chat := Counts{InputTokens: 10, OutputTokens: 2, Requests: 1}
	got := WithResponsesImageGen(chat, []byte(`{"response":{"tool_usage":{"image_gen":{"input_tokens":5,"output_tokens":100}}}}`))
	if got.InputTokens != 10 || got.ImageGenTextInputTokens != 5 || got.ImageGenOutputTokens != 100 || got.Requests != 1 {
		t.Fatalf("%+v", got)
	}
	if WithResponsesImageGen(chat, []byte(`{"type":"x"}`)) != chat {
		t.Fatal("no image usage must leave counts untouched")
	}
	if got := WithResponsesImageGen(Counts{}, []byte(`{"tool_usage":{"image_gen":{"output_tokens":1}}}`)); got.Requests != 1 {
		t.Fatalf("image-only payload not counted as a request: %+v", got)
	}
}
