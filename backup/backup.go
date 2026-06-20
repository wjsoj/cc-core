// Package backup ships an app's critical persistent state off-host to an
// S3-compatible bucket (Bitiful), asymmetrically encrypted, with date-stamped
// objects and a rolling retention window. It is the disaster-recovery layer:
// with the project code plus the newest object in the bucket, an operator can
// rebuild a wiped server (see each app's DR.md).
//
// Pipeline (RunBackup):
//
//	files → tar.gz → seal(recipient pubkey) → PUT <prefix>YYYY-MM-DD.tar.gz.enc → prune > retention
//
// Pruning runs only AFTER a successful upload, so a failed backup can never
// delete the previous good copy. The archive is small (a few MB) so it is
// buffered in memory rather than streamed.
//
// Encryption is asymmetric (X25519 NaCl sealed box — see crypt.go): the
// server holds only the recipient public key. The matching private key is
// kept offline and is required only for Restore, so a server or
// bucket-credential compromise cannot read historical backups.
package backup

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
)

const (
	objectSuffix = ".tar.gz.enc"
	dateLayout   = "2006-01-02"
)

// Options is one backup invocation.
type Options struct {
	S3              S3Config
	RecipientPubKey string    // base64 X25519 public key (encrypt-only)
	RetentionDays   int       // rolling window; <=0 keeps everything
	Now             time.Time // injectable for tests; zero = time.Now().UTC()
}

func (o Options) now() time.Time {
	if o.Now.IsZero() {
		return time.Now().UTC()
	}
	return o.Now.UTC()
}

// BackupObject is one stored backup, newest-Date first when sorted by
// ListBackups.
type BackupObject struct {
	Key  string
	Date time.Time
	Size int64
}

// RunBackup archives entries, seals to opt.RecipientPubKey, uploads to
// "<prefix>YYYY-MM-DD.tar.gz.enc", then prunes objects older than
// RetentionDays. Returns the object key written.
func RunBackup(ctx context.Context, opt Options, entries []FileEntry) (string, error) {
	if opt.RecipientPubKey == "" {
		return "", fmt.Errorf("backup: recipient_pubkey is required (refusing to upload plaintext)")
	}
	if len(entries) == 0 {
		return "", fmt.Errorf("backup: no files to back up")
	}
	cli, err := NewS3Client(opt.S3)
	if err != nil {
		return "", fmt.Errorf("backup: s3 client: %w", err)
	}
	key := opt.S3.normPrefix() + opt.now().Format(dateLayout) + objectSuffix

	// tar.gz → seal → upload (buffered; archive is small).
	var tgz bytes.Buffer
	if err := writeTarGz(&tgz, entries); err != nil {
		return "", fmt.Errorf("backup: archive: %w", err)
	}
	sealed, err := sealTo(tgz.Bytes(), opt.RecipientPubKey)
	if err != nil {
		return "", fmt.Errorf("backup: encrypt: %w", err)
	}
	_, err = cli.PutObject(ctx, opt.S3.Bucket, key, bytes.NewReader(sealed), int64(len(sealed)), minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return "", fmt.Errorf("backup: upload %s: %w", key, err)
	}

	if opt.RetentionDays > 0 {
		if err := prune(ctx, cli, opt.S3, opt.now(), opt.RetentionDays); err != nil {
			// Upload succeeded; a prune failure is non-fatal (next run retries).
			return key, fmt.Errorf("backup: uploaded %s but prune failed: %w", key, err)
		}
	}
	return key, nil
}

// ListBackups returns the backups under the configured prefix, newest first.
func ListBackups(ctx context.Context, cfg S3Config) ([]BackupObject, error) {
	cli, err := NewS3Client(cfg)
	if err != nil {
		return nil, err
	}
	return listBackups(ctx, cli, cfg)
}

func listBackups(ctx context.Context, cli *minio.Client, cfg S3Config) ([]BackupObject, error) {
	prefix := cfg.normPrefix()
	var out []BackupObject
	for obj := range cli.ListObjects(ctx, cfg.Bucket, minio.ListObjectsOptions{
		Prefix:    prefix,
		Recursive: true,
	}) {
		if obj.Err != nil {
			return nil, obj.Err
		}
		d, ok := parseKeyDate(obj.Key)
		if !ok {
			continue
		}
		out = append(out, BackupObject{Key: obj.Key, Date: d, Size: obj.Size})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Date.After(out[j].Date) })
	return out, nil
}

// prune deletes objects whose embedded date is strictly older than
// now - retentionDays.
func prune(ctx context.Context, cli *minio.Client, cfg S3Config, now time.Time, retentionDays int) error {
	objs, err := listBackups(ctx, cli, cfg)
	if err != nil {
		return err
	}
	cutoff := now.AddDate(0, 0, -retentionDays)
	for _, o := range objs {
		if o.Date.Before(cutoff) {
			if err := cli.RemoveObject(ctx, cfg.Bucket, o.Key, minio.RemoveObjectOptions{}); err != nil {
				return fmt.Errorf("prune %s: %w", o.Key, err)
			}
		}
	}
	return nil
}

// Restore downloads a backup (a specific "YYYY-MM-DD" date or "latest"),
// decrypts it with the supplied identity (offline private key, base64), and
// extracts it into destDir. Used for disaster recovery.
func Restore(ctx context.Context, cfg S3Config, identityPriv, dateOrLatest, destDir string) error {
	cli, err := NewS3Client(cfg)
	if err != nil {
		return err
	}
	key, err := resolveKey(ctx, cli, cfg, dateOrLatest)
	if err != nil {
		return err
	}
	obj, err := cli.GetObject(ctx, cfg.Bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return fmt.Errorf("restore: get %s: %w", key, err)
	}
	defer obj.Close()
	sealed, err := io.ReadAll(obj)
	if err != nil {
		return fmt.Errorf("restore: download %s: %w", key, err)
	}
	plain, err := openFrom(sealed, identityPriv)
	if err != nil {
		return fmt.Errorf("restore: decrypt %s: %w", key, err)
	}
	if err := extractTarGz(bytes.NewReader(plain), destDir); err != nil {
		return fmt.Errorf("restore: extract %s: %w", key, err)
	}
	return nil
}

func resolveKey(ctx context.Context, cli *minio.Client, cfg S3Config, dateOrLatest string) (string, error) {
	if d := strings.TrimSpace(dateOrLatest); d != "" && !strings.EqualFold(d, "latest") {
		return cfg.normPrefix() + d + objectSuffix, nil
	}
	objs, err := listBackups(ctx, cli, cfg)
	if err != nil {
		return "", err
	}
	if len(objs) == 0 {
		return "", fmt.Errorf("restore: no backups found under prefix %q", cfg.normPrefix())
	}
	return objs[0].Key, nil // newest first
}

// parseKeyDate extracts the YYYY-MM-DD date from a backup object key
// ("<prefix>YYYY-MM-DD.tar.gz.age").
func parseKeyDate(key string) (time.Time, bool) {
	base := path.Base(key)
	if !strings.HasSuffix(base, objectSuffix) {
		return time.Time{}, false
	}
	stamp := strings.TrimSuffix(base, objectSuffix)
	d, err := time.Parse(dateLayout, stamp)
	if err != nil {
		return time.Time{}, false
	}
	return d, true
}
