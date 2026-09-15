# Payment capture review (2026-09-15)

This is a protocol review, not proof of a successful live payment or a 403 fix.
The preceding local subscription test returned account/entitlement data, but
not the independent subscriptions portal payload. That result does not establish
checkout authorization or payment eligibility.

## Evidence (private captures, not copied into source)

| Capture row | Step | Finding |
| --- | --- | --- |
| Not captured | Create checkout | Request body comes from the bookmarklet; no original request to claim full parity against. |
| 129 | Taxes | Current JSON field names and nested billing address match captured structure. |
| 152 | Confirmation token | Browser used Stripe.js, Elements session context, and a verification token. Current raw Go form is not equivalent. |
| 174 | OpenAI confirm | Current `confirm_token`, session ID and payment method field names match. |
| 178 | Stripe confirm | Core fields match; SDK/session context is not reproduced by Go. |
| 201 | Final status | `status` and `payment_status` are present; require `complete` plus `paid`. |

Matching field names does not prove upstream acceptance. Do not replay captured
cookies, challenge tokens, client secrets, device identities or SDK-identification
strings. Do not use random billing addresses in live payment requests.

Stripe documents generating ConfirmationTokens via Stripe.js and Payment Element:
https://docs.stripe.com/payments/finalize-payments-on-the-server
This is not evidence that embedding another merchant's payment integration on
our domain is authorized or supported. For ChatGPT, official checkout remains
the user-controlled path for browser/bank verification.

## Changes in this patch

- Request JSON and identity encoding without claiming a browser/SDK identity.
- Return typed, redacted `UpstreamError` with operation, status and classification.
- Distinguish 401, 403, explicit challenge markers, 429 and invalid JSON.
- HTML alone is not classified as proof of Cloudflare or of a challenge.
- Retain fixed proxy/direct routing, no fallback, no application retries,
  no redirect following and persistent confirmation guards.
- Regression tests stop the payment sequence on 403 at every pre/confirmation
  stage and check that response bodies and identifiers are not exposed.

This patch improves diagnosis and failure handling, not upstream permissions.
No live checkout, card tokenization or payment was attempted in this review.
No production deployment was performed.
