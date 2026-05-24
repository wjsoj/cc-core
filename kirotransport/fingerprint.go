// Package kirotransport holds the transport-layer primitives shared by all
// Kiro API clients: pinned client-fingerprint constants, AWS SigV4 v4 signer,
// and helpers for building Smithy + AWS-SDK headers.
//
// Two client flavors are supported:
//
//   - IDE flavor — matches kiro.rs (KiroIDE in UA). aws-sdk-js/1.0.34 user-agent
//     family. Used when proxying for the desktop IDE.
//   - CLI flavor — matches the kiro-cli capture under crack/kiro/. aws-sdk-rust/1.3.16
//     user-agent family. KIRO-CLI/2.4.1.
//
// Both flavors call the SAME endpoints with the SAME body shapes — the only
// differences are User-Agent, x-amz-user-agent, and a few flavor-specific
// headers (e.g. CLI omits x-amzn-kiro-agent-mode that IDE sends).
//
// Bumping kiro-cli or kiro IDE versions is a one-place change here.
package kirotransport

// Pinned version targets. Re-verify on every kiro / kiro-cli release.
const (
	// KiroIDEVersion is the IDE client version reported in the UA.
	// Update when KiroIDE bumps; matches kiro.rs config.kiroVersion default.
	KiroIDEVersion = "0.2.43"

	// KiroCLIVersion is the kiro-cli release captured under crack/kiro/.
	KiroCLIVersion = "2.4.1"

	// AWSSDKJSVersion is the aws-sdk-js version used by KiroIDE.
	AWSSDKJSVersion = "1.0.34"

	// AWSSDKRustVersion is the aws-sdk-rust version used by KIRO-CLI 2.4.1.
	AWSSDKRustVersion = "1.3.16"

	// NodeJSVersion is the Node.js runtime version reported by KiroIDE.
	NodeJSVersion = "20.18.1"

	// RustVersion is the rustc/lang version segment used in CLI UAs.
	RustVersion = "1.92.0"

	// CodeWhispererStreamingVersion is the api/ segment in the real CLI UA
	// (captured as "codewhispererstreaming/0.1.16551"). Independent from
	// AWSSDKRustVersion — bump separately if the capture changes.
	CodeWhispererStreamingVersion = "0.1.16551"

	// CLIAppLabel is the app/ segment in the real CLI UA. Confirms which
	// CLI surface the request comes from (kiro-cli identifies as AmazonQ-For-CLI).
	CLIAppLabel = "AmazonQ-For-CLI"

	// SystemSegment is "os/linux" — kiro-cli does not include a kernel version.
	SystemSegment = "os/linux"
)

// Flavor identifies which CC-style client we are mimicking.
type Flavor uint8

const (
	// FlavorIDE — proxies the Kiro IDE. UA family: aws-sdk-js + KiroIDE.
	FlavorIDE Flavor = iota
	// FlavorCLI — proxies the kiro-cli. UA family: aws-sdk-rust + KIRO-CLI.
	FlavorCLI
)

// Service constants from the Smithy / CodeWhisperer wire protocol.
const (
	// SmithyJSON10 is the Content-Type for x-amz-json-1.0 endpoints
	// (GenerateAssistantResponse, ListAvailableModels, SendTelemetryEvent).
	SmithyJSON10 = "application/x-amz-json-1.0"

	// SmithyJSON11 is the Content-Type for x-amz-json-1.1 endpoints
	// (Cognito GetId / GetCredentialsForIdentity).
	SmithyJSON11 = "application/x-amz-json-1.1"

	// EventStreamContentType is the response Content-Type for
	// GenerateAssistantResponse streaming bodies.
	EventStreamContentType = "application/vnd.amazon.eventstream"
)

// Target codes for x-amz-target. Verified against crack/kiro/rows/.
//
// Note: CodeWhisperer exposes TWO service surfaces:
//   - AmazonCodeWhispererService (sync RPC calls)
//   - AmazonCodeWhispererStreamingService (streaming responses)
//
// GenerateAssistantResponse lives in Streaming; ListAvailableModels and
// SendTelemetryEvent live in Service. This matches both the captured wire
// targets (crack/kiro/rows/03, 06, 07) and the AWS SDK service manifest.
const (
	TargetGenerateAssistantResponse = "AmazonCodeWhispererStreamingService.GenerateAssistantResponse"
	TargetListAvailableModels       = "AmazonCodeWhispererService.ListAvailableModels"
	TargetSendTelemetryEvent        = "AmazonCodeWhispererService.SendTelemetryEvent"

	// Cognito IdentityService targets (x-amz-json-1.1).
	TargetCognitoGetID                     = "AWSCognitoIdentityService.GetId"
	TargetCognitoGetCredentialsForIdentity = "AWSCognitoIdentityService.GetCredentialsForIdentity"
)
