package mimicry

import (
	"crypto/sha256"
	"encoding/hex"
)

// SimIdentity carries the stable per-account fingerprint values that the
// mimicry layer needs from the upstream Auth. Splitting it out of any
// auth.Auth type keeps this package framework-free.
//
//   - AccountKey: the most stable per-account anchor (account_uuid >
//     email > id); device_id is sha256 over this and stays constant for
//     the lifetime of the account, even when multiple downstream client
//     tokens are routed through it.
//   - AccountUUID: the real OAuth-issued UUID when known, written verbatim
//     into metadata.user_id.account_uuid. Empty string means "unknown"
//     and matches real CC's behavior on a brand-new login before the
//     bootstrap roundtrip has populated it.
//   - ClientToken: the downstream caller identity. Each distinct
//     ClientToken looks like a separate concurrent CC window on the same
//     device, which is what we want when N users share one OAuth account.
type SimIdentity struct {
	AccountKey  string
	AccountUUID string
	ClientToken string
}

// DeviceIDFor maps an account anchor to a stable 64-char hex device id.
// Same account → same device_id forever, matching the machine-id sha256
// that real CC writes. Use the same anchor across every request from
// this account so X-Claude-Code-Session-Id and metadata.user_id agree.
func DeviceIDFor(accountKey string) string {
	sum := sha256.Sum256([]byte("cpa-claude-device/" + accountKey))
	return hex.EncodeToString(sum[:])
}

// SessionIDFor derives a UUIDv4-shaped session id keyed by:
//   - account (so different accounts never share session ids)
//   - downstream client token (so concurrent users on the same account
//     present as separate windows of one CC instance)
//   - first user message hash (so multi-turn conversations keep one
//     session, but switching topics rotates to a new one)
//
// Stable across repeated requests of the same conversation — the real
// CLI keeps the value steady for the entire `claude` invocation.
func SessionIDFor(id SimIdentity, body []byte) string {
	first := extractFirstUserText(body)
	convHash := sha256.Sum256([]byte(first))
	h := sha256.New()
	h.Write([]byte("cpa-claude-session/"))
	h.Write([]byte(id.AccountKey))
	h.Write([]byte("|"))
	h.Write([]byte(id.ClientToken))
	h.Write([]byte("|"))
	h.Write(convHash[:])
	sum := h.Sum(nil)
	return uuidFromBytes(sum[:16])
}
