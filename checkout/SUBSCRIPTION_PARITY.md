# Read-only subscription capture comparison

## Evidence and scope

`crack/chatgpt-checkout/rows/199` records a successful browser GET to
`/backend-api/accounts/check/v4-2023-04-27?timezone_offset_min=420`.
Row 196 records `/backend-api/accounts/optimized/check`; its response schema is
different and it is not a drop-in replacement for `accounts/check`.
This capture does **not** contain `/backend-api/subscriptions`.

The HTTP metadata profile is pinned to row 199 (Chrome 148/macOS). Browser
timezone is supplied by the caller rather than hardcoding the captured 420.
No captured Cookie, session/device identifiers, observation tokens, client
build identifier, or checkout/verify Referer is replayed. That historical
Referer includes a different order's secret. Compression remains `identity`
because the existing response reader does not decode Brotli.

This is partial HTTP-request parity, not an emulation of a complete logged-in
browser or a demonstrated fix for production HTTP 403 responses. It does not
alter TLS, solve challenges, change proxy routing, or modify payment requests.
The browser-context probe skips the saved-payment-method request because the
GPTPay view does not display cards. The existing admin probe retains its prior
behavior when the optional browser context is absent.

The user also supplied a successful browser GET to
`/backend-api/subscriptions/auto_top_up/settings?include_payment_method=false`.
Its response describes auto-reload settings, not plan/term/invoices. In that
response `is_enabled:false` does not establish whether the account has Plus,
and `payment_method:null` with `include_payment_method=false` does not establish
whether a card is saved. That request has newer browser/client metadata and
live browser cookies. It does not prove which individual header caused the
earlier 403, nor establish `/subscriptions` success. No credentials from that
request are stored here or used in regression tests.

## Local integration

GPTPay forwards `Date.getTimezoneOffset()` for subscription queries. It now
retains billing period, currency, purchase channel and renewal/expiration data
from `accounts/check` even if the separate portal call fails. Missing groups
are marked unknown/partial rather than reported as false/free. Subscription
errors expose status codes without raw upstream HTML or credentials.

Tests use re-identified fixtures and in-process transports only. Live fetching
is not part of unit tests. The local hypitoken checkout temporarily uses its
sibling cc-core through `replace`; publish and pin an approved cc-core version
before removing that development replacement. These changes have not been
deployed or demonstrated to clear the production 403.
