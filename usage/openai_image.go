package usage

import "encoding/json"

// imageGenUsage is the token block OpenAI reports for image generation, both
// as `tool_usage.image_gen` on a Responses turn and as `usage` on the Images
// API. The details split is optional; a block without it bills its input as
// text, the cheaper and more common case.
type imageGenUsage struct {
	InputTokens        int64 `json:"input_tokens"`
	InputTokensDetails *struct {
		TextTokens  int64 `json:"text_tokens"`
		ImageTokens int64 `json:"image_tokens"`
	} `json:"input_tokens_details"`
	OutputTokens int64 `json:"output_tokens"`
}

func (u *imageGenUsage) counts() Counts {
	if u == nil {
		return Counts{}
	}
	text, image := u.InputTokens, int64(0)
	if d := u.InputTokensDetails; d != nil && d.TextTokens+d.ImageTokens > 0 {
		text, image = d.TextTokens, d.ImageTokens
	}
	return Counts{
		ImageGenTextInputTokens:  max(text, 0),
		ImageGenImageInputTokens: max(image, 0),
		ImageGenOutputTokens:     max(u.OutputTokens, 0),
	}
}

type toolUsage struct {
	ImageGen *imageGenUsage `json:"image_gen"`
}

// ParseResponsesImageGenUsage reads `tool_usage.image_gen` off a Responses
// payload: the streaming terminal event ({"response":{"tool_usage":…}}) or a
// non-stream body ({"tool_usage":…}). Zero when absent — every non-terminal
// frame, and every turn that generated nothing.
func ParseResponsesImageGenUsage(payload []byte) Counts {
	if len(payload) == 0 {
		return Counts{}
	}
	var wrap struct {
		ToolUsage *toolUsage `json:"tool_usage"`
		Response  struct {
			ToolUsage *toolUsage `json:"tool_usage"`
		} `json:"response"`
	}
	if json.Unmarshal(payload, &wrap) != nil {
		return Counts{}
	}
	tu := wrap.Response.ToolUsage
	if tu == nil {
		tu = wrap.ToolUsage
	}
	if tu == nil {
		return Counts{}
	}
	return tu.ImageGen.counts()
}

// ParseImagesAPIUsage reads the `usage` block of an Images API response
// (/v1/images/generations, /v1/images/edits, and the Codex backend's mirror of
// them), or of the terminal `image_generation.completed` stream event. Only
// meaningful for those endpoints: a Responses body also has a `usage`, but
// that one bills the chat model and must go through the caller's own parser.
func ParseImagesAPIUsage(payload []byte) Counts {
	if len(payload) == 0 {
		return Counts{}
	}
	var wrap struct {
		Usage *imageGenUsage `json:"usage"`
	}
	if json.Unmarshal(payload, &wrap) != nil {
		return Counts{}
	}
	return wrap.Usage.counts()
}

// WithResponsesImageGen folds a Responses payload's `tool_usage.image_gen`
// into c, the chat usage already read off the same payload. The block sits
// beside `usage` and bills at the image card; a relay that reads only `usage`
// gives every generated image away. A payload that carries image usage counts
// as one observed request even if its chat usage was empty.
func WithResponsesImageGen(c Counts, payload []byte) Counts {
	ig := ParseResponsesImageGenUsage(payload)
	if !ig.HasImageGen() {
		return c
	}
	c.ImageGenTextInputTokens = ig.ImageGenTextInputTokens
	c.ImageGenImageInputTokens = ig.ImageGenImageInputTokens
	c.ImageGenOutputTokens = ig.ImageGenOutputTokens
	c.Requests = 1
	return c
}
