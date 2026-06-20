package backup

import (
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3Config is the connection + addressing info for the backup bucket. It
// mirrors the config.yaml `backup.s3` block after @path resolution. Bitiful
// (s3.bitiful.net) is S3-compatible, so the same struct works for any
// S3-compatible endpoint.
type S3Config struct {
	Endpoint        string // host only, no scheme — e.g. "s3.bitiful.net"
	Region          string // e.g. "cn-east-1"
	Bucket          string // e.g. "apibackup"
	AccessKeyID     string
	SecretAccessKey string
	// Prefix namespaces one app's objects inside a shared bucket, e.g.
	// "cpa-claude/" or "hypitoken/". Normalized to end with a single "/".
	Prefix string
	// PlainHTTP forces http:// instead of https://. Default (false) = HTTPS,
	// which is what Bitiful requires; only set this for a local test server.
	PlainHTTP bool
}

// normPrefix returns the prefix with no leading slash and exactly one
// trailing slash (empty stays empty).
func (c S3Config) normPrefix() string {
	p := strings.TrimSpace(c.Prefix)
	p = strings.Trim(p, "/")
	if p == "" {
		return ""
	}
	return p + "/"
}

// NewS3Client builds a minio client for the configured endpoint. SigV4 with
// static credentials; TLS on unless PlainHTTP is set.
func NewS3Client(cfg S3Config) (*minio.Client, error) {
	return minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		Secure: !cfg.PlainHTTP,
		Region: cfg.Region,
	})
}
