package kirotransport

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
)

// UserAgent builds the high-level User-Agent string for the given flavor.
//
// CLI (matches crack/kiro/rows/06):
//
//	aws-sdk-rust/1.3.16 ua/2.1 api/codewhispererstreaming/0.1.16551
//	os/linux lang/rust/1.92.0 md/appVersion-2.4.1 app/AmazonQ-For-CLI
//
// IDE (matches kiro.rs ide.rs):
//
//	aws-sdk-js/1.0.34 ua/2.1 os/linux lang/js md/nodejs#20.18.1
//	api/codewhispererstreaming#1.0.34 m/E KiroIDE-0.2.43-<machineID>
//
// machineID can be any stable per-account string (typically sha256 of
// refreshToken, matching kiro.rs MachineId derivation). Ignored for FlavorCLI.
func UserAgent(flavor Flavor, machineID string) string {
	switch flavor {
	case FlavorCLI:
		return fmt.Sprintf(
			"aws-sdk-rust/%s ua/2.1 api/codewhispererstreaming/%s %s lang/rust/%s md/appVersion-%s app/%s",
			AWSSDKRustVersion, CodeWhispererStreamingVersion, SystemSegment, RustVersion, KiroCLIVersion, CLIAppLabel,
		)
	default: // FlavorIDE
		return fmt.Sprintf(
			"aws-sdk-js/%s ua/2.1 os/linux lang/js md/nodejs#%s api/codewhispererstreaming#%s m/E KiroIDE-%s-%s",
			AWSSDKJSVersion, NodeJSVersion, AWSSDKJSVersion, KiroIDEVersion, machineID,
		)
	}
}

// XAmzUserAgent builds the short x-amz-user-agent header value.
//
// CLI (matches capture):
//
//	aws-sdk-rust/1.3.16 ua/2.1 api/codewhispererstreaming/0.1.16551
//	os/linux lang/rust/1.92.0 m/F app/AmazonQ-For-CLI
//
// IDE (matches kiro.rs):
//
//	aws-sdk-js/1.0.34 KiroIDE-0.2.43-<machineID>
func XAmzUserAgent(flavor Flavor, machineID string) string {
	switch flavor {
	case FlavorCLI:
		return fmt.Sprintf(
			"aws-sdk-rust/%s ua/2.1 api/codewhispererstreaming/%s %s lang/rust/%s m/F app/%s",
			AWSSDKRustVersion, CodeWhispererStreamingVersion, SystemSegment, RustVersion, CLIAppLabel,
		)
	default:
		return fmt.Sprintf("aws-sdk-js/%s KiroIDE-%s-%s", AWSSDKJSVersion, KiroIDEVersion, machineID)
	}
}

// NewInvocationID returns a fresh UUIDv4 suitable for amz-sdk-invocation-id.
func NewInvocationID() string { return uuidv4() }

// ApplyCommonAWSHeaders sets the headers every AWS SDK request carries:
// amz-sdk-invocation-id, amz-sdk-request, User-Agent, x-amz-user-agent.
//
// Does NOT set Authorization, Content-Type, x-amz-target — those are
// caller-specific.
func ApplyCommonAWSHeaders(req *http.Request, flavor Flavor, machineID string) {
	req.Header.Set("User-Agent", UserAgent(flavor, machineID))
	req.Header.Set("x-amz-user-agent", XAmzUserAgent(flavor, machineID))
	req.Header.Set("amz-sdk-invocation-id", NewInvocationID())
	req.Header.Set("amz-sdk-request", "attempt=1; max=3")
}

// ApplySmithyHeaders sets Content-Type + x-amz-target for a Smithy JSON
// 1.0 or 1.1 RPC call.
func ApplySmithyHeaders(req *http.Request, contentType, amzTarget string) {
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("x-amz-target", amzTarget)
}

// ApplyBearerAuth sets "Authorization: Bearer <token>" and, when isAPIKey
// is true, also sets the tokentype: API_KEY header that kiro-cli sends for
// ksk_ credentials.
func ApplyBearerAuth(req *http.Request, token string, isAPIKey bool) {
	req.Header.Set("Authorization", "Bearer "+token)
	if isAPIKey {
		req.Header.Set("tokentype", "API_KEY")
	}
}

// uuidv4 returns a random UUIDv4 with the standard hyphenated 8-4-4-4-12 format.
func uuidv4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	var dst [36]byte
	hex.Encode(dst[0:8], b[0:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], b[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], b[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], b[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:36], b[10:16])
	return string(dst[:])
}
