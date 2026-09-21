package apicompat

import "encoding/json"

// ResponseError is a terminal upstream failure, not an assistant completion.
// Both HTTP aggregation and streaming adapters use it to avoid reporting a
// failed agent turn as finish_reason=stop.
type ResponseError struct {
	Message string          `json:"message"`
	Type    string          `json:"type"`
	Code    string          `json:"code,omitempty"`
	Param   json.RawMessage `json:"param,omitempty"`
}

func (e *ResponseError) Error() string { return e.Message }

// ResponseFailure accepts Responses lifecycle events and bare response objects.
// Incomplete responses are valid partial results, not errors.
func ResponseFailure(payload []byte) *ResponseError {
	var v struct {
		Type     string          `json:"type"`
		Status   json.RawMessage `json:"status"`
		Error    *ResponseError  `json:"error"`
		Message  string          `json:"message"`
		Code     string          `json:"code"`
		Response *struct {
			Status string         `json:"status"`
			Error  *ResponseError `json:"error"`
		} `json:"response"`
	}
	if json.Unmarshal(payload, &v) != nil {
		return nil
	}
	failure := v.Error
	var status string
	_ = json.Unmarshal(v.Status, &status)
	if v.Response != nil {
		status = v.Response.Status
		if v.Response.Error != nil {
			failure = v.Response.Error
		}
	}
	if failure == nil {
		switch v.Type {
		case "error", "response.failed", "response.cancelled", "response.canceled":
		default:
			if status != "failed" && status != "cancelled" && status != "canceled" {
				return nil
			}
		}
		failure = &ResponseError{Message: v.Message, Code: v.Code}
	}
	if failure.Message == "" {
		failure.Message = "The upstream response failed before completion."
	}
	if failure.Type == "" {
		failure.Type = "server_error"
	}
	return failure
}

func (e *ResponseError) frames() [][]byte {
	payload, _ := json.Marshal(struct {
		Error *ResponseError `json:"error"`
	}{e})
	return [][]byte{sseFrame(payload), DoneFrame}
}
