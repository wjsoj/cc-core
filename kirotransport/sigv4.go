package kirotransport

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWSCredentials carries the four-field STS / IAM credential bundle.
// SessionToken is empty for long-lived (non-STS) credentials.
type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// SignV4 signs req in place using the AWS Signature V4 process.
//
// Service is the AWS service code ("execute-api" for client-telemetry,
// "cognito-identity" for Cognito, etc). Region is the standard AWS region
// code (e.g. "us-east-1"). signTime is the wall-clock used for the
// X-Amz-Date header; pass time.Now() in production.
//
// payload is required (pass nil for empty bodies). If req has a body and
// payload is nil, the body is read into memory and replaced; this means
// SignV4 must be called before sending and is NOT zero-copy.
//
// Headers set/overwritten: Host, X-Amz-Date, Authorization, and
// X-Amz-Security-Token when SessionToken is non-empty.
//
// This is the minimal subset of SigV4 we need for Kiro's
// client-telemetry endpoint; we do not implement chunked signing or
// presigned URLs.
func SignV4(req *http.Request, creds AWSCredentials, service, region string, signTime time.Time, payload []byte) error {
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return fmt.Errorf("kirotransport: SignV4: empty credentials")
	}
	if req.URL == nil {
		return fmt.Errorf("kirotransport: SignV4: nil URL")
	}

	// Read body if payload wasn't passed in.
	if payload == nil && req.Body != nil {
		body, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return fmt.Errorf("kirotransport: SignV4: read body: %w", err)
		}
		payload = body
		req.Body = io.NopCloser(bytes.NewReader(payload))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(payload)), nil }
		req.ContentLength = int64(len(payload))
	}
	if payload == nil {
		payload = []byte{}
	}

	ts := signTime.UTC()
	amzDate := ts.Format("20060102T150405Z")
	dateStamp := ts.Format("20060102")

	// Always set Host explicitly so it ends up in SignedHeaders.
	host := req.URL.Host
	if req.Host != "" {
		host = req.Host
	}
	req.Header.Set("Host", host)
	req.Header.Set("X-Amz-Date", amzDate)
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}

	payloadHash := hexSHA256(payload)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	canonicalReq, signedHeaders := buildCanonicalRequest(req, payloadHash)
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		hexSHA256([]byte(canonicalReq)),
	}, "\n")

	signingKey := deriveSigningKey(creds.SecretAccessKey, dateStamp, region, service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	auth := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		creds.AccessKeyID, credentialScope, signedHeaders, signature,
	)
	req.Header.Set("Authorization", auth)
	return nil
}

func buildCanonicalRequest(req *http.Request, payloadHash string) (canonical string, signedHeaders string) {
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	canonicalURI := canonicalPath(req.URL.Path)
	canonicalQuery := canonicalQueryString(req.URL.Query())

	// Sort lowercased header names; values trimmed of surrounding whitespace.
	type hkv struct{ k, v string }
	var hs []hkv
	for name, values := range req.Header {
		lower := strings.ToLower(name)
		// Skip Authorization (we're computing it) and User-Agent (boto/sdk convention).
		if lower == "authorization" || lower == "user-agent" {
			continue
		}
		joined := strings.Join(trimAll(values), ",")
		hs = append(hs, hkv{k: lower, v: joined})
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i].k < hs[j].k })

	var sb strings.Builder
	var sigNames []string
	for _, h := range hs {
		sb.WriteString(h.k)
		sb.WriteString(":")
		sb.WriteString(h.v)
		sb.WriteString("\n")
		sigNames = append(sigNames, h.k)
	}
	signedHeaders = strings.Join(sigNames, ";")
	canonical = strings.Join([]string{
		method,
		canonicalURI,
		canonicalQuery,
		sb.String(), // already ends with \n
		signedHeaders,
		payloadHash,
	}, "\n")
	return canonical, signedHeaders
}

func canonicalPath(p string) string {
	if p == "" {
		return "/"
	}
	// SigV4 keeps the path as-is, but each segment must be URI-encoded
	// per RFC 3986 (excluding "/"). Double-encoding intentionally:
	// callers requesting "/api/foo bar" should send "/api/foo%20bar".
	return uriEncodePath(p)
}

func canonicalQueryString(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		values := q[k]
		sort.Strings(values)
		for _, v := range values {
			parts = append(parts, uriEncode(k, true)+"="+uriEncode(v, true))
		}
	}
	return strings.Join(parts, "&")
}

func uriEncodePath(p string) string {
	// Encode each segment between "/" separately.
	var sb strings.Builder
	for i := 0; i < len(p); {
		if p[i] == '/' {
			sb.WriteByte('/')
			i++
			continue
		}
		j := i
		for j < len(p) && p[j] != '/' {
			j++
		}
		sb.WriteString(uriEncode(p[i:j], false))
		i = j
	}
	if sb.Len() == 0 {
		return "/"
	}
	return sb.String()
}

func uriEncode(s string, encodeSlash bool) string {
	const hexChars = "0123456789ABCDEF"
	var out []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'),
			c == '-', c == '_', c == '.', c == '~':
			out = append(out, c)
		case c == '/' && !encodeSlash:
			out = append(out, c)
		default:
			out = append(out, '%', hexChars[c>>4], hexChars[c&0x0f])
		}
	}
	return string(out)
}

func trimAll(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = collapseInternalSpaces(strings.TrimSpace(v))
	}
	return out
}

func collapseInternalSpaces(s string) string {
	// SigV4 requires collapsing runs of spaces inside a value.
	if !strings.Contains(s, "  ") {
		return s
	}
	var sb strings.Builder
	space := false
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			if space {
				continue
			}
			space = true
		} else {
			space = false
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func deriveSigningKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}
