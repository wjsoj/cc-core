package mimicry

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// RequestClass is derived from the original body and shared by the body and
// header layers. Headers are deliberately not trusted for classification.
type RequestClass uint8

const (
	RequestClassUnknown RequestClass = iota
	RequestClassGeneric
	RequestClassGenuine
)

func (c RequestClass) String() string {
	switch c {
	case RequestClassGeneric:
		return "generic"
	case RequestClassGenuine:
		return "genuine"
	default:
		return "unknown"
	}
}

// GenuineRequestMode controls the only two supported treatments of an
// official Claude Code body. Rewrite only accepts the custom-base-url shape
// emitted without first-party cch or cc_prev_req fields.
type GenuineRequestMode uint8

const (
	GenuineRequestModeUnspecified GenuineRequestMode = iota
	GenuineRequestPreserve
	GenuineRequestRewrite

	// GenuineRequestRewriteStripCCH is kept as a source-compatibility alias for
	// consumers built against the original experiment name.
	// Deprecated: use GenuineRequestRewrite.
	GenuineRequestRewriteStripCCH = GenuineRequestRewrite
)

func (m GenuineRequestMode) String() string {
	switch m {
	case GenuineRequestPreserve:
		return "preserve"
	case GenuineRequestRewrite:
		return "rewrite"
	default:
		return "unspecified"
	}
}

// GenericRequestMode controls treatment of a non-Claude-Code messages body.
// Legacy preserves the historical best-effort transformer. Synthesize is the
// fail-closed account-bound path used before sending generic traffic through
// an Anthropic OAuth credential.
type GenericRequestMode uint8

const (
	GenericRequestLegacy GenericRequestMode = iota
	GenericRequestSynthesize
)

func (m GenericRequestMode) String() string {
	if m == GenericRequestSynthesize {
		return "synthesize"
	}
	return "legacy"
}

// RequestPolicy is created once after classifying the original body. Its
// fields are private so callers cannot fabricate a class/mode combination.
type RequestPolicy struct {
	class       RequestClass
	genuineMode GenuineRequestMode
	genericMode GenericRequestMode
	valid       bool
}

func NewClaudeCodeRequestPolicy(class RequestClass, genuineMode GenuineRequestMode) (RequestPolicy, error) {
	switch class {
	case RequestClassGeneric:
		if genuineMode != GenuineRequestModeUnspecified &&
			genuineMode != GenuineRequestPreserve &&
			genuineMode != GenuineRequestRewrite {
			return RequestPolicy{}, fmt.Errorf("unsupported genuine request mode: %d", genuineMode)
		}
		return RequestPolicy{class: class, genuineMode: GenuineRequestModeUnspecified, valid: true}, nil
	case RequestClassGenuine:
		if genuineMode != GenuineRequestPreserve && genuineMode != GenuineRequestRewrite {
			return RequestPolicy{}, fmt.Errorf("unsupported genuine request mode: %d", genuineMode)
		}
		return RequestPolicy{class: class, genuineMode: genuineMode, valid: true}, nil
	default:
		return RequestPolicy{}, errors.New("cannot create a policy for an unknown Claude request class")
	}
}

// NewGenericClaudeCodeSynthesizePolicy returns the strict policy for generic
// traffic selected onto an Anthropic OAuth credential. It is intentionally a
// separate constructor so existing callers of NewClaudeCodeRequestPolicy keep
// the legacy best-effort generic behavior until they opt in.
func NewGenericClaudeCodeSynthesizePolicy() RequestPolicy {
	return RequestPolicy{
		class:       RequestClassGeneric,
		genericMode: GenericRequestSynthesize,
		valid:       true,
	}
}

func (p RequestPolicy) Class() RequestClass             { return p.class }
func (p RequestPolicy) GenuineMode() GenuineRequestMode { return p.genuineMode }
func (p RequestPolicy) GenericMode() GenericRequestMode { return p.genericMode }
func (p RequestPolicy) IsValid() bool                   { return p.valid }

// BodyTransformResult is an opaque prepared request. The header layer accepts
// only a valid result produced by PrepareClaudeCodeRequest, which prevents a
// failed rewrite from silently falling back to a mismatched identity.
type BodyTransformResult struct {
	body                   []byte
	bodyDigest             [sha256.Size]byte
	policy                 RequestPolicy
	identity               SimIdentity
	credentialAccountKey   string
	credentialKind         string
	sessionID              string
	accountIdentityApplied bool
	valid                  bool
}

func (r BodyTransformResult) Body() []byte                 { return r.body }
func (r BodyTransformResult) Policy() RequestPolicy        { return r.policy }
func (r BodyTransformResult) SessionID() string            { return r.sessionID }
func (r BodyTransformResult) AccountIdentityApplied() bool { return r.accountIdentityApplied }
func (r BodyTransformResult) IsValid() bool                { return r.valid }

// HashClaudeAccountKey returns a privacy-safe stable account identifier for
// experiment/audit logs. It never exposes an OAuth UUID, email, or credential
// filename.
func HashClaudeAccountKey(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("claude-account-key/v1\x00" + value))
	return fmt.Sprintf("%x", sum[:8])
}

// ClassifyClaudeCodeRequest classifies a non-null JSON object from body
// content only. A billing attribution block is the stable primary signal; the
// known official system-prefix families remain the fallback for main, agent,
// explore/title, and compact Claude Code requests, including Haiku side calls.
func ClassifyClaudeCodeRequest(body []byte) RequestClass {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
		return RequestClassUnknown
	}
	if systemHasBillingBlock(obj["system"]) || hasClaudeCodeSystemPrefix(obj["system"]) {
		return RequestClassGenuine
	}
	return RequestClassGeneric
}

// ClaudeCodeSourceSessionID returns the genuine client's metadata session.
// Consumers should prefer it over a conflicting ingress header when keying
// sticky slots, because the prepared header layer also treats the body as the
// source of truth.
func ClaudeCodeSourceSessionID(body []byte) (string, bool) {
	if ClassifyClaudeCodeRequest(body) != RequestClassGenuine {
		return "", false
	}
	identity, err := metadataIdentityFromBody(body)
	if err != nil || strings.TrimSpace(identity.SessionID) == "" {
		return "", false
	}
	return identity.SessionID, true
}

// PrepareClaudeCodeRequest binds body policy, selected account identity, and
// the credential's stable account key/kind into one opaque result. The bearer
// token is deliberately supplied later at Apply time because OAuth refresh may
// rotate it while the caller waits for sidecar bootstrap.
//
// Generic requests retain the existing mimicry behavior. Genuine preserve
// returns the exact input bytes. Genuine rewrite replaces the metadata identity
// with the selected OAuth account, maps the genuine source session into that
// account's namespace, and pins the billing version. First-party-only cch and
// cc_prev_req fields are rejected because custom-base-url Claude Code requests
// do not emit them and the proxy cannot safely regenerate or rebind them.
//
// Any error returns an unusable zero result. The caller must stop this attempt;
// it must not send the original body as an implicit preserve fallback, switch
// credentials, or blame the selected credential for a local preparation error.
func PrepareClaudeCodeRequest(body []byte, model string, id SimIdentity, policy RequestPolicy, credentialKind string) (BodyTransformResult, error) {
	if !policy.valid {
		return BodyTransformResult{}, errors.New("invalid Claude request policy")
	}
	if strings.TrimSpace(id.AccountKey) == "" {
		return BodyTransformResult{}, errors.New("empty upstream credential account key")
	}
	if credentialKind != KindOAuth && credentialKind != KindAPIKey {
		return BodyTransformResult{}, fmt.Errorf("unsupported upstream credential kind %q", credentialKind)
	}
	actualClass := ClassifyClaudeCodeRequest(body)
	if actualClass != policy.class {
		return BodyTransformResult{}, fmt.Errorf("claude request class changed: policy=%s body=%s", policy.class, actualClass)
	}

	switch policy.class {
	case RequestClassGeneric:
		if policy.genericMode == GenericRequestSynthesize {
			return transformGenericSynthesize(body, id, policy, credentialKind)
		}
		out := ApplyClaudeCodeBodyMimicry(body, model, id)
		return newBodyTransformResult(out, policy, id, credentialKind, "", false), nil
	case RequestClassGenuine:
		switch policy.genuineMode {
		case GenuineRequestPreserve:
			source, _ := metadataIdentityFromBody(body)
			return newBodyTransformResult(body, policy, id, credentialKind, source.SessionID, false), nil
		case GenuineRequestRewrite:
			return transformGenuineRewrite(body, id, policy, credentialKind)
		default:
			return BodyTransformResult{}, fmt.Errorf("unsupported genuine request mode: %d", policy.genuineMode)
		}
	default:
		return BodyTransformResult{}, errors.New("cannot transform an unknown Claude request class")
	}
}

func transformGenuineRewrite(body []byte, id SimIdentity, policy RequestPolicy, credentialKind string) (BodyTransformResult, error) {
	if credentialKind != KindOAuth {
		return BodyTransformResult{}, errors.New("rewrite requires an OAuth credential")
	}
	if strings.TrimSpace(id.AccountKey) == "" {
		return BodyTransformResult{}, errors.New("rewrite requires a non-empty account key")
	}
	if strings.TrimSpace(id.AccountUUID) == "" {
		return BodyTransformResult{}, errors.New("rewrite requires the OAuth account UUID")
	}
	if strings.TrimSpace(id.ClientToken) == "" {
		return BodyTransformResult{}, errors.New("rewrite requires a downstream client token")
	}
	source, err := metadataIdentityFromBody(body)
	if err != nil || strings.TrimSpace(source.SessionID) == "" {
		if err == nil {
			err = errors.New("metadata.user_id.session_id is empty")
		}
		return BodyTransformResult{}, fmt.Errorf("rewrite requires a genuine source session: %w", err)
	}
	targetSession := SessionIDForSource(id, source.SessionID)
	out, err := rewriteGenuineIdentity(body, id, targetSession)
	if err != nil {
		return BodyTransformResult{}, err
	}
	return newBodyTransformResult(out, policy, id, credentialKind, targetSession, true), nil
}

func transformGenericSynthesize(body []byte, id SimIdentity, policy RequestPolicy, credentialKind string) (BodyTransformResult, error) {
	if credentialKind != KindOAuth {
		return BodyTransformResult{}, errors.New("generic synthesis requires an OAuth credential")
	}
	if strings.TrimSpace(id.AccountKey) == "" {
		return BodyTransformResult{}, errors.New("generic synthesis requires a non-empty account key")
	}
	if strings.TrimSpace(id.AccountUUID) == "" {
		return BodyTransformResult{}, errors.New("generic synthesis requires the OAuth account UUID")
	}
	if strings.TrimSpace(id.ClientToken) == "" {
		return BodyTransformResult{}, errors.New("generic synthesis requires a downstream client token")
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
		return BodyTransformResult{}, errors.New("generic body is not a JSON object")
	}
	var messages []json.RawMessage
	rawMessages, ok := obj["messages"]
	trimmedMessages := bytes.TrimSpace(rawMessages)
	if !ok || len(trimmedMessages) == 0 || trimmedMessages[0] != '[' || json.Unmarshal(rawMessages, &messages) != nil {
		return BodyTransformResult{}, errors.New("generic body requires a messages array")
	}

	sessionID := SessionIDFor(id, body)
	originalBlocks := extractSystemBlocks(obj["system"])
	stripCacheControlFromBlocks(originalBlocks)
	applySystemCacheBreakpoints(originalBlocks)
	billing := buildExternalBillingBlock(body, CLICurrentVersion)
	blocks := []json.RawMessage{billing, buildSystemTextBlock(ClaudeCodeSystemPrompt, false, false)}
	blocks = append(blocks, originalBlocks...)
	rawSystem, err := json.Marshal(blocks)
	if err != nil {
		return BodyTransformResult{}, fmt.Errorf("marshal generic system: %w", err)
	}
	obj["system"] = rawSystem

	metadata := make(map[string]json.RawMessage)
	if raw := obj["metadata"]; len(raw) > 0 && string(raw) != "null" {
		// Preserve unrelated metadata fields when it is an object. Any other
		// shape is replaced so an unparseable downstream identity can never leak.
		_ = json.Unmarshal(raw, &metadata)
		if metadata == nil {
			metadata = make(map[string]json.RawMessage)
		}
	}
	userID := buildJSONUserID(DeviceIDFor(id.AccountKey), id.AccountUUID, sessionID)
	metadata["user_id"], err = json.Marshal(userID)
	if err != nil {
		return BodyTransformResult{}, fmt.Errorf("marshal generic metadata.user_id: %w", err)
	}
	obj["metadata"], err = json.Marshal(metadata)
	if err != nil {
		return BodyTransformResult{}, fmt.Errorf("marshal generic metadata: %w", err)
	}

	out, err := json.Marshal(obj)
	if err != nil {
		return BodyTransformResult{}, fmt.Errorf("marshal generic body: %w", err)
	}
	out = stripMessageCacheControl(out)
	out = addMessageCacheBreakpoints(out)
	if !metadataMatchesIdentity(out, id, sessionID) {
		return BodyTransformResult{}, errors.New("refusing partial generic synthesis: metadata verification failed")
	}
	if err := verifyRewrittenBilling(out); err != nil {
		return BodyTransformResult{}, fmt.Errorf("refusing partial generic synthesis: %w", err)
	}
	return newBodyTransformResult(out, policy, id, credentialKind, sessionID, true), nil
}

// buildExternalBillingBlock matches the custom-base-url Claude Code shape:
// account attribution and entrypoint are present, while first-party-only cch
// and cc_prev_req are absent because a relay cannot regenerate or rebind them.
func buildExternalBillingBlock(body []byte, cliVersion string) json.RawMessage {
	fingerprint := computeClaudeCodeFingerprint(body, cliVersion)
	text := fmt.Sprintf("x-anthropic-billing-header: cc_version=%s.%s; cc_entrypoint=cli;", cliVersion, fingerprint)
	out, _ := json.Marshal(map[string]any{"type": "text", "text": text})
	return out
}

func newBodyTransformResult(body []byte, policy RequestPolicy, id SimIdentity, credentialKind, sessionID string, identityApplied bool) BodyTransformResult {
	return BodyTransformResult{
		body:                   body,
		bodyDigest:             sha256.Sum256(body),
		policy:                 policy,
		identity:               id,
		credentialAccountKey:   id.AccountKey,
		credentialKind:         credentialKind,
		sessionID:              sessionID,
		accountIdentityApplied: identityApplied,
		valid:                  true,
	}
}

// ApplyClaudeCodePreparedRequest atomically installs the prepared body and
// applies headers from that same result. It validates everything before
// mutating req, then copies the body so later caller mutation cannot create a
// header/body mismatch.
func ApplyClaudeCodePreparedRequest(req *http.Request, credentialToken, credentialAccountKey, credentialKind string, stream, isAnthropicBase bool, result BodyTransformResult) error {
	if req == nil {
		return errors.New("nil upstream request")
	}
	if err := validatePreparedResult(result); err != nil {
		return err
	}
	if strings.TrimSpace(credentialToken) == "" {
		return errors.New("empty upstream credential")
	}
	if credentialAccountKey != result.credentialAccountKey || credentialKind != result.credentialKind {
		return errors.New("prepared request credential binding mismatch")
	}
	if result.policy.class == RequestClassGenuine && result.policy.genuineMode == GenuineRequestRewrite &&
		(req.Header == nil || strings.TrimSpace(req.Header.Get("Anthropic-Beta")) == "") {
		// Genuine CC request betas are a request-class/context feature vector,
		// not one global version constant (main, 1M, and title differ). Without
		// the downstream vector we cannot safely synthesize the right 2.1.220
		// list, so fail closed instead of defaulting every request to Full.
		return errors.New("genuine rewrite requires the downstream Anthropic-Beta feature vector")
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}

	switch result.policy.class {
	case RequestClassGeneric:
		ApplyClaudeCodeHeaders(req, credentialToken, credentialKind, stream, isAnthropicBase, result.identity, result.body)
		if result.policy.genericMode == GenericRequestSynthesize {
			// Generic ingress headers are not evidence of a real Claude Code
			// feature/profile vector. Replace every identity-bearing value with the
			// same pinned profile and account-bound session used by the body.
			forcePinnedClaudeCodeProfile(req.Header)
			req.Header.Set("Anthropic-Beta", ClaudeAnthropicBetaFull)
			req.Header.Set("Accept", "application/json")
			req.Header.Set("X-Claude-Code-Session-Id", result.sessionID)
			if isAnthropicBase {
				req.Header.Set("x-client-request-id", NewRequestUUID())
			}
		}
	case RequestClassGenuine:
		if result.policy.genuineMode == GenuineRequestPreserve {
			// Preserve the genuine client's own version/profile headers. Only the
			// upstream credential is necessarily replaced; body session is the
			// authority when an intermediary supplied a conflicting header.
			applyCredentialHeader(req.Header, credentialToken, credentialKind)
			if req.Header.Get("Content-Type") == "" {
				req.Header.Set("Content-Type", "application/json")
			}
			if result.sessionID != "" {
				req.Header.Set("X-Claude-Code-Session-Id", result.sessionID)
			}
		} else if result.policy.genuineMode != GenuineRequestRewrite || !result.accountIdentityApplied {
			return errors.New("invalid prepared genuine rewrite")
		} else {
			ApplyClaudeCodeHeaders(req, credentialToken, credentialKind, stream, isAnthropicBase, result.identity, result.body)
			forcePinnedClaudeCodeProfile(req.Header)
			req.Header.Set("Accept", "application/json")
			req.Header.Set("X-Claude-Code-Session-Id", result.sessionID)
		}
	default:
		return errors.New("invalid prepared request class")
	}
	installPreparedBody(req, result.body)
	return nil
}

func installPreparedBody(req *http.Request, body []byte) {
	owned := bytes.Clone(body)
	req.Body = io.NopCloser(bytes.NewReader(owned))
	req.ContentLength = int64(len(owned))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(owned)), nil
	}
}

func validatePreparedResult(result BodyTransformResult) error {
	if !result.valid || !result.policy.valid || result.body == nil || result.credentialAccountKey == "" {
		return errors.New("unprepared Claude request")
	}
	if result.credentialKind != KindOAuth && result.credentialKind != KindAPIKey {
		return errors.New("prepared Claude request has an invalid credential kind")
	}
	if sha256.Sum256(result.body) != result.bodyDigest {
		return errors.New("prepared Claude request body was mutated")
	}
	preparedClass := ClassifyClaudeCodeRequest(result.body)
	if result.policy.class == RequestClassGeneric && result.policy.genericMode == GenericRequestSynthesize {
		if preparedClass != RequestClassGenuine {
			return errors.New("prepared generic synthesis is not a Claude Code body")
		}
	} else if preparedClass != result.policy.class {
		return errors.New("prepared Claude request class no longer matches its body")
	}
	if result.policy.class == RequestClassGeneric && result.policy.genericMode == GenericRequestSynthesize {
		if result.credentialKind != KindOAuth || !result.accountIdentityApplied || result.sessionID == "" {
			return errors.New("prepared generic synthesis has no OAuth account identity")
		}
		if !metadataMatchesIdentity(result.body, result.identity, result.sessionID) {
			return errors.New("prepared generic synthesis metadata no longer matches its account identity")
		}
		if err := verifyRewrittenBilling(result.body); err != nil {
			return fmt.Errorf("prepared generic synthesis billing verification failed: %w", err)
		}
	}
	if result.policy.class == RequestClassGenuine && result.policy.genuineMode == GenuineRequestRewrite {
		if !result.accountIdentityApplied || result.sessionID == "" {
			return errors.New("prepared rewrite has no account identity")
		}
		if !metadataMatchesIdentity(result.body, result.identity, result.sessionID) {
			return errors.New("prepared rewrite metadata no longer matches its account identity")
		}
		if err := verifyRewrittenBilling(result.body); err != nil {
			return fmt.Errorf("prepared rewrite billing verification failed: %w", err)
		}
	}
	return nil
}

func applyCredentialHeader(h http.Header, token, kind string) {
	if kind == KindAPIKey {
		h.Del("Authorization")
		h.Set("x-api-key", token)
		return
	}
	h.Del("x-api-key")
	h.Set("Authorization", "Bearer "+token)
}

func rewriteGenuineIdentity(body []byte, id SimIdentity, sessionID string) ([]byte, error) {
	if !json.Valid(body) {
		return nil, errors.New("genuine body is not a JSON object")
	}

	metadataSpan, err := requireJSONObjectMemberSpan(body, "metadata")
	if err != nil {
		return nil, err
	}
	userIDSpan, err := requireJSONObjectMemberSpan(body[metadataSpan.start:metadataSpan.end], "user_id")
	if err != nil {
		return nil, fmt.Errorf("metadata: %w", err)
	}
	userIDSpan.start += metadataSpan.start
	userIDSpan.end += metadataSpan.start

	systemSpan, err := requireJSONObjectMemberSpan(body, "system")
	if err != nil {
		return nil, err
	}
	rawSystem := body[systemSpan.start:systemSpan.end]
	firstBlockSpan, err := requireJSONArrayElementSpan(rawSystem, 0)
	if err != nil {
		return nil, fmt.Errorf("system: %w", err)
	}
	firstBlock := rawSystem[firstBlockSpan.start:firstBlockSpan.end]
	textSpan, err := requireJSONObjectMemberSpan(firstBlock, "text")
	if err != nil {
		return nil, fmt.Errorf("system[0]: %w", err)
	}
	textSpan.start += systemSpan.start + firstBlockSpan.start
	textSpan.end += systemSpan.start + firstBlockSpan.start

	parsed, _, _, err := parseSingleBillingSystem(rawSystem)
	if err != nil {
		return nil, err
	}
	for _, field := range parsed.fields {
		if field.key == "cch" || field.key == "cc_prev_req" {
			return nil, fmt.Errorf("genuine rewrite does not accept first-party billing field %q", field.key)
		}
	}
	rewrittenBilling, err := parsed.rewritten(computeClaudeCodeFingerprint(body, CLICurrentVersion))
	if err != nil {
		return nil, fmt.Errorf("rewrite billing header: %w", err)
	}
	encodedBilling, err := json.Marshal(rewrittenBilling)
	if err != nil {
		return nil, fmt.Errorf("marshal billing text: %w", err)
	}

	userID := buildJSONUserID(DeviceIDFor(id.AccountKey), id.AccountUUID, sessionID)
	encodedUserID, err := json.Marshal(userID)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata.user_id: %w", err)
	}
	out, err := applyByteReplacements(body, []byteReplacement{
		{start: userIDSpan.start, end: userIDSpan.end, value: encodedUserID},
		{start: textSpan.start, end: textSpan.end, value: encodedBilling},
	})
	if err != nil {
		return nil, fmt.Errorf("rewrite genuine body: %w", err)
	}
	if !metadataMatchesIdentity(out, id, sessionID) {
		return nil, errors.New("refusing partial identity rewrite: metadata verification failed")
	}
	if err := verifyRewrittenBilling(out); err != nil {
		return nil, fmt.Errorf("refusing partial identity rewrite: %w", err)
	}
	return out, nil
}

type metadataIdentity struct {
	DeviceID    string `json:"device_id"`
	AccountUUID string `json:"account_uuid"`
	SessionID   string `json:"session_id"`
}

func metadataIdentityFromBody(body []byte) (metadataIdentity, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
		return metadataIdentity{}, errors.New("body is not a JSON object")
	}
	var md map[string]json.RawMessage
	if err := json.Unmarshal(obj["metadata"], &md); err != nil || md == nil {
		return metadataIdentity{}, errors.New("metadata is not an object")
	}
	var userID string
	if err := json.Unmarshal(md["user_id"], &userID); err != nil || userID == "" {
		return metadataIdentity{}, errors.New("metadata.user_id is not a non-empty JSON string")
	}
	var identity metadataIdentity
	if err := json.Unmarshal([]byte(userID), &identity); err != nil {
		return metadataIdentity{}, fmt.Errorf("metadata.user_id is not valid identity JSON: %w", err)
	}
	return identity, nil
}

type jsonValueSpan struct {
	start int
	end   int
}

func requireJSONObjectMemberSpan(data []byte, name string) (jsonValueSpan, error) {
	if !json.Valid(data) {
		return jsonValueSpan{}, errors.New("value is not valid JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	opening, err := dec.Token()
	if err != nil || opening != json.Delim('{') {
		return jsonValueSpan{}, errors.New("value is not a JSON object")
	}
	var found jsonValueSpan
	count := 0
	for dec.More() {
		keyToken, tokenErr := dec.Token()
		if tokenErr != nil {
			return jsonValueSpan{}, tokenErr
		}
		key, ok := keyToken.(string)
		if !ok {
			return jsonValueSpan{}, errors.New("JSON object key is not a string")
		}
		span, spanErr := decodeRawValueSpan(dec, data)
		if spanErr != nil {
			return jsonValueSpan{}, spanErr
		}
		if key == name {
			count++
			found = span
		}
	}
	if _, err = dec.Token(); err != nil {
		return jsonValueSpan{}, err
	}
	if count == 0 {
		return jsonValueSpan{}, fmt.Errorf("JSON object has no %q field", name)
	}
	if count != 1 {
		return jsonValueSpan{}, fmt.Errorf("JSON object has duplicate %q fields", name)
	}
	return found, nil
}

func requireJSONArrayElementSpan(data []byte, index int) (jsonValueSpan, error) {
	if index < 0 || !json.Valid(data) {
		return jsonValueSpan{}, errors.New("value is not a valid JSON array")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	opening, err := dec.Token()
	if err != nil || opening != json.Delim('[') {
		return jsonValueSpan{}, errors.New("value is not a JSON array")
	}
	var found jsonValueSpan
	foundElement := false
	for i := 0; dec.More(); i++ {
		span, spanErr := decodeRawValueSpan(dec, data)
		if spanErr != nil {
			return jsonValueSpan{}, spanErr
		}
		if i == index {
			found = span
			foundElement = true
		}
	}
	if _, err = dec.Token(); err != nil {
		return jsonValueSpan{}, err
	}
	if !foundElement {
		return jsonValueSpan{}, fmt.Errorf("JSON array has no element %d", index)
	}
	return found, nil
}

func decodeRawValueSpan(dec *json.Decoder, data []byte) (jsonValueSpan, error) {
	before := int(dec.InputOffset())
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return jsonValueSpan{}, err
	}
	after := int(dec.InputOffset())
	if before < 0 || after < before || after > len(data) || len(raw) == 0 {
		return jsonValueSpan{}, errors.New("invalid JSON decoder offsets")
	}
	relativeStart := bytes.LastIndex(data[before:after], raw)
	if relativeStart < 0 {
		return jsonValueSpan{}, errors.New("could not locate raw JSON value")
	}
	start := before + relativeStart
	return jsonValueSpan{start: start, end: start + len(raw)}, nil
}

type byteReplacement struct {
	start int
	end   int
	value []byte
}

func applyByteReplacements(src []byte, replacements []byteReplacement) ([]byte, error) {
	replacements = append([]byteReplacement(nil), replacements...)
	sort.Slice(replacements, func(i, j int) bool { return replacements[i].start < replacements[j].start })

	capacity := len(src)
	previousEnd := 0
	for _, replacement := range replacements {
		if replacement.start < previousEnd || replacement.start < 0 || replacement.end < replacement.start || replacement.end > len(src) {
			return nil, errors.New("invalid or overlapping byte replacements")
		}
		capacity += len(replacement.value) - (replacement.end - replacement.start)
		previousEnd = replacement.end
	}
	if capacity < 0 {
		return nil, errors.New("invalid replacement result size")
	}

	out := make([]byte, 0, capacity)
	previousEnd = 0
	for _, replacement := range replacements {
		out = append(out, src[previousEnd:replacement.start]...)
		out = append(out, replacement.value...)
		previousEnd = replacement.end
	}
	out = append(out, src[previousEnd:]...)
	return out, nil
}

func trimmedStringSpan(value string, start, end int) (int, int) {
	trimmed := strings.TrimSpace(value[start:end])
	if trimmed == "" {
		return end, end
	}
	offset := strings.Index(value[start:end], trimmed)
	return start + offset, start + offset + len(trimmed)
}

type billingField struct {
	key        string
	value      string
	valueStart int
	valueEnd   int
}

type billingHeader struct {
	text   string
	fields []billingField
}

const billingHeaderPrefix = "x-anthropic-billing-header:"

func parseBillingText(text string) (billingHeader, bool, error) {
	trimStart, trimEnd := trimmedStringSpan(text, 0, len(text))
	if trimStart == trimEnd || !strings.HasPrefix(text[trimStart:trimEnd], billingHeaderPrefix) {
		return billingHeader{}, false, nil
	}
	cursor := trimStart + len(billingHeaderPrefix)
	if cursor >= trimEnd || text[trimEnd-1] != ';' {
		return billingHeader{}, true, errors.New("billing header must end with a semicolon")
	}

	fields := make([]billingField, 0, 5)
	seen := make(map[string]bool, 5)
	for cursor < trimEnd {
		semicolonOffset := strings.IndexByte(text[cursor:trimEnd], ';')
		if semicolonOffset < 0 {
			return billingHeader{}, true, errors.New("billing header must end with a semicolon")
		}
		semicolon := cursor + semicolonOffset
		fieldStart, fieldEnd := trimmedStringSpan(text, cursor, semicolon)
		if fieldStart == fieldEnd {
			return billingHeader{}, true, errors.New("billing header contains an empty field")
		}
		equalsOffset := strings.IndexByte(text[fieldStart:fieldEnd], '=')
		if equalsOffset < 0 {
			return billingHeader{}, true, fmt.Errorf("malformed billing field %q", text[fieldStart:fieldEnd])
		}
		equals := fieldStart + equalsOffset
		keyStart, keyEnd := trimmedStringSpan(text, fieldStart, equals)
		valueStart, valueEnd := trimmedStringSpan(text, equals+1, fieldEnd)
		if keyStart == keyEnd || valueStart == valueEnd {
			return billingHeader{}, true, fmt.Errorf("malformed billing field %q", text[fieldStart:fieldEnd])
		}
		normalizedKey := strings.ToLower(text[keyStart:keyEnd])
		if seen[normalizedKey] {
			return billingHeader{}, true, fmt.Errorf("duplicate billing field %q", normalizedKey)
		}
		seen[normalizedKey] = true
		fields = append(fields, billingField{
			key:        normalizedKey,
			value:      text[valueStart:valueEnd],
			valueStart: valueStart,
			valueEnd:   valueEnd,
		})
		cursor = semicolon + 1
	}
	if !seen["cc_version"] {
		return billingHeader{}, true, errors.New("billing header has no cc_version field")
	}
	if !seen["cc_entrypoint"] {
		return billingHeader{}, true, errors.New("billing header has no cc_entrypoint field")
	}
	parsed := billingHeader{text: text}
	parsed.fields = fields
	for _, field := range fields {
		switch field.key {
		case "cc_entrypoint":
			// Claude Code 2.1.220 uses "cli" for interactive sessions and
			// "sdk-cli" for the official --print/Agent SDK path. Both are
			// genuine first-party request shapes; retain the source value so
			// the rewritten billing block stays consistent with its caller.
			if field.value != "cli" && field.value != "sdk-cli" {
				return billingHeader{}, true, fmt.Errorf("unsupported cc_entrypoint %q", field.value)
			}
		}
	}
	return parsed, true, nil
}

func (b billingHeader) rewritten(fingerprint string) (string, error) {
	replacements := make([]byteReplacement, 0, 1)
	for _, field := range b.fields {
		switch field.key {
		case "cc_version":
			replacements = append(replacements, byteReplacement{
				start: field.valueStart,
				end:   field.valueEnd,
				value: []byte(CLICurrentVersion + "." + fingerprint),
			})
		}
	}
	out, err := applyByteReplacements([]byte(b.text), replacements)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func parseSingleBillingSystem(rawSystem json.RawMessage) (billingHeader, []json.RawMessage, map[string]json.RawMessage, error) {
	var blocks []json.RawMessage
	if err := json.Unmarshal(rawSystem, &blocks); err != nil || len(blocks) == 0 {
		return billingHeader{}, nil, nil, errors.New("genuine system is not a non-empty block array")
	}
	var first map[string]json.RawMessage
	if err := json.Unmarshal(blocks[0], &first); err != nil || first == nil {
		return billingHeader{}, nil, nil, errors.New("system[0] is not an object")
	}
	var blockType, text string
	if err := json.Unmarshal(first["type"], &blockType); err != nil || blockType != "text" {
		return billingHeader{}, nil, nil, errors.New("system[0] is not a text block")
	}
	if err := json.Unmarshal(first["text"], &text); err != nil {
		return billingHeader{}, nil, nil, errors.New("system[0].text is not a string")
	}
	parsed, isBilling, err := parseBillingText(text)
	if err != nil {
		return billingHeader{}, nil, nil, err
	}
	if !isBilling {
		return billingHeader{}, nil, nil, errors.New("system[0] is not a billing block")
	}
	for i := 1; i < len(blocks); i++ {
		var block map[string]json.RawMessage
		if err := json.Unmarshal(blocks[i], &block); err != nil || block == nil {
			continue
		}
		var candidate string
		if err := json.Unmarshal(block["text"], &candidate); err != nil {
			continue
		}
		_, isExtraBilling, parseErr := parseBillingText(candidate)
		if parseErr != nil {
			return billingHeader{}, nil, nil, fmt.Errorf("system[%d]: %w", i, parseErr)
		}
		if isExtraBilling {
			return billingHeader{}, nil, nil, errors.New("genuine system contains multiple billing blocks")
		}
	}
	return parsed, blocks, first, nil
}

func verifyRewrittenBilling(body []byte) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
		return errors.New("rewritten body is not a JSON object")
	}
	parsed, _, _, err := parseSingleBillingSystem(obj["system"])
	if err != nil {
		return err
	}
	expectedVersion := CLICurrentVersion + "." + computeClaudeCodeFingerprint(body, CLICurrentVersion)
	for _, field := range parsed.fields {
		if field.key == "cch" || field.key == "cc_prev_req" {
			return fmt.Errorf("unsupported first-party billing field %q remains", field.key)
		}
		if field.key == "cc_version" && field.value != expectedVersion {
			return fmt.Errorf("billing version %q does not match %q", field.value, expectedVersion)
		}
	}
	return nil
}

func metadataMatchesIdentity(body []byte, id SimIdentity, sessionID string) bool {
	identity, err := metadataIdentityFromBody(body)
	if err != nil {
		return false
	}
	return identity.DeviceID == DeviceIDFor(id.AccountKey) &&
		identity.AccountUUID == id.AccountUUID &&
		identity.SessionID == sessionID
}

func forcePinnedClaudeCodeProfile(h http.Header) {
	h.Set("User-Agent", ClaudeCLIUserAgent)
	h.Set("Anthropic-Version", ClaudeAnthropicVersion)
	h.Set("X-App", "cli")
	h.Set("X-Stainless-Retry-Count", ClaudeStainlessRetryCnt)
	h.Set("X-Stainless-Lang", ClaudeStainlessLang)
	h.Set("X-Stainless-Runtime", ClaudeStainlessRuntime)
	h.Set("X-Stainless-Runtime-Version", ClaudeStainlessRuntimeV)
	h.Set("X-Stainless-Package-Version", ClaudeStainlessPackageV)
	h.Set("X-Stainless-Os", ClaudeStainlessOS)
	h.Set("X-Stainless-Arch", ClaudeStainlessArch)
	h.Set("X-Stainless-Timeout", ClaudeStainlessTimeout)
}
