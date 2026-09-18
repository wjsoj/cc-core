package checkout

// PaymentIntent contains only the non-identifying fields needed to interpret
// Stripe's business outcome. HTTP 200 is not evidence of a successful payment.
// In particular, the captured verify_challenge response returned HTTP 200 with
// requires_payment_method and payment_intent_authentication_failure.
type PaymentIntent struct {
	Status           string                `json:"status"`
	LastPaymentError *PaymentIntentFailure `json:"last_payment_error"`
}

// Deliberately do not decode message, payment_method, client_secret or next_action
// payloads here. They may contain personal data or authentication material.
type PaymentIntentFailure struct {
	Code        string `json:"code"`
	DeclineCode string `json:"decline_code"`
}

// Result never declares checkout paid: the caller must independently verify
// OpenAI checkout status == complete and payment_status == paid. Error codes
// are allowlisted and messages are local, not verbatim upstream text.
func (p PaymentIntent) Result() PaymentResult {
	r := PaymentResult{State: "unknown"}
	switch p.Status {
	case "requires_action":
		r.State = p.Status
		r.Message = "需要在官方结账页完成支付验证，可能是验证码或银行验证；尚未确认支付成功。"
	case "requires_payment_method":
		r.State = p.Status
		r.Message = "支付方式未通过，请核对官方结账结果；不要自动重试付款。"
		if p.LastPaymentError != nil {
			switch p.LastPaymentError.Code {
			case "payment_intent_authentication_failure":
				r.ErrorCode = p.LastPaymentError.Code
				// This code is not CAPTCHA-specific. The live captured message was
				// CAPTCHA failure, but a future response may describe bank auth.
				r.Message = "支付验证失败，可能涉及验证码或银行验证；请在官方页面核验，不能据此判断余额不足。"
			case "card_declined":
				r.ErrorCode = "card_declined"
				r.Message = "银行卡被拒绝，请核对官方提示或联系发卡方。"
				if p.LastPaymentError.DeclineCode == "insufficient_funds" {
					r.ErrorCode = "insufficient_funds"
					r.Message = "发卡方返回余额不足；本次未确认支付成功。"
				}
			case "expired_card":
				r.ErrorCode = "expired_card"
				r.Message = "卡片已过期，请在官方页面核对付款方式。"
			case "incorrect_cvc":
				r.ErrorCode = "incorrect_cvc"
				r.Message = "卡片安全码未通过校验，请在官方页面核对。"
			}
		}
	case "canceled":
		r.State = p.Status
	case "succeeded", "processing":
		r.State = "processing"
	}
	return r
}
