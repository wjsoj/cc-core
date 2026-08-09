// Package backup ships an app's critical persistent state off-host to an
// S3-compatible bucket (Bitiful), asymmetrically encrypted, with date-stamped
// objects and a rolling retention window. It is the disaster-recovery layer:
// with the project code plus the newest object in the bucket, an operator can
// rebuild a wiped server (see each app's DR.md).
//
// Pipeline (RunBackup):
//
//	files → tar.gz → seal(recipient pubkey) → PUT <prefix>YYYY-MM-DDTHHMMSSZ.tar.gz.enc → prune > retention
//
// Pruning runs only AFTER a successful upload, so a failed backup can never
// delete the previous good copy. The archive is small (a few MB) so it is
// buffered in memory rather than streamed.
//
// # Why the key carries a time, not just a date
//
// It used to be "<prefix>YYYY-MM-DD" — one object per day, so a second run on
// the same date silently replaced the first. That is the wrong failure mode for
// a disaster-recovery layer: the day you most want a backup is the day
// something went wrong, and on that day there is very likely a second run —
// an operator verifying the pipeline, a retried timer, a manual invocation
// after a deploy. On 2026-08-09 exactly that happened: a morning backup held
// the last good copy of a database, an evening verification run overwrote it
// with the already-damaged state, and the good copy was gone.
//
// A timestamped key cannot collide, so no run can ever destroy an earlier one;
// retention alone decides what leaves the bucket. Legacy date-only keys still
// parse (as midnight UTC) so old objects stay listable, restorable and
// prunable.
//
// A date on its own remains a valid restore target: it resolves to the NEWEST
// run of that day. Use ListBackups (exposed as `<binary> backup list`) to see
// every run and pass an exact stem when a specific one is wanted.
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
	// stampLayout is what new objects are named with. Colons are legal in an
	// S3 key but awkward in a shell and in some tooling, so the time is
	// written compactly; the trailing Z is a reminder that it is UTC.
	stampLayout = "2006-01-02T150405Z"
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
	Key string
	// Date is the moment the object is named for: the full timestamp for
	// current keys, midnight UTC for legacy date-only ones.
	Date time.Time
	Size int64
	// Legacy marks an object written under the old one-per-day scheme, which
	// could be overwritten by a same-day rerun.
	Legacy bool
}

// Day is the retention bucket the object falls in.
func (b BackupObject) Day() string { return b.Date.UTC().Format(dateLayout) }

// RunBackup archives entries, seals to opt.RecipientPubKey, uploads to
// "<prefix>YYYY-MM-DDTHHMMSSZ.tar.gz.enc", then prunes objects older than
// RetentionDays. Returns the object key written.
//
// The key carries the time, so a run never overwrites an earlier one — see the
// package comment for why that matters.
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
	key := opt.S3.normPrefix() + opt.now().Format(stampLayout) + objectSuffix

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
		d, legacy, ok := parseKeyDate(obj.Key)
		if !ok {
			continue
		}
		out = append(out, BackupObject{Key: obj.Key, Date: d, Size: obj.Size, Legacy: legacy})
	}
	sortObjs(out)
	return out, nil
}

// sortObjs orders newest first. Split out from listBackups so the ordering the
// restore path depends on can be tested without an S3 round trip.
func sortObjs(objs []BackupObject) {
	sort.Slice(objs, func(i, j int) bool {
		if !objs[i].Date.Equal(objs[j].Date) {
			return objs[i].Date.After(objs[j].Date)
		}
		// A legacy key sharing a day with timestamped runs sorts to midnight
		// and is therefore already last; break any remaining tie on the key so
		// listings do not jitter between calls.
		return objs[i].Key > objs[j].Key
	})
}

// prune deletes objects whose embedded date is strictly older than
// now - retentionDays.
//
// Both sides are truncated to the day, so retention stays a count of calendar
// days and does not start depending on the clock time a run happened to fire
// at — which it would if a timestamped key were compared against a timestamped
// cutoff. Every run of a day therefore expires together.
func prune(ctx context.Context, cli *minio.Client, cfg S3Config, now time.Time, retentionDays int) error {
	objs, err := listBackups(ctx, cli, cfg)
	if err != nil {
		return err
	}
	cutoff := now.UTC().AddDate(0, 0, -retentionDays).Truncate(24 * time.Hour)
	for _, o := range objs {
		if o.Date.UTC().Truncate(24 * time.Hour).Before(cutoff) {
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

// resolveKey turns a restore target into an object key.
//
// Accepted: "latest" (or empty) for the newest object anywhere in the prefix,
// a bare "YYYY-MM-DD" for the newest RUN of that day, or an exact stem
// ("YYYY-MM-DDTHHMMSSZ") to pin one specific run. The day form is the one an
// operator reaches for, and there can now be several runs behind it — picking
// the newest matches what "the backup from that day" has always meant, and
// `backup list` is how to see the others.
func resolveKey(ctx context.Context, cli *minio.Client, cfg S3Config, dateOrLatest string) (string, error) {
	want := strings.TrimSpace(dateOrLatest)
	objs, err := listBackups(ctx, cli, cfg)
	if err != nil {
		return "", err
	}
	return pickKey(objs, cfg.normPrefix(), want)
}

// pickKey is resolveKey's decision, over an already-sorted listing.
func pickKey(objs []BackupObject, prefix, want string) (string, error) {
	if len(objs) == 0 {
		return "", fmt.Errorf("restore: no backups found under prefix %q", prefix)
	}
	if want == "" || strings.EqualFold(want, "latest") {
		return objs[0].Key, nil // newest first
	}
	// A bare date means "that day", and is checked FIRST — deliberately.
	//
	// A legacy object's own key is a bare date, so matching exact stems first
	// would make "2026-08-09" resolve to the legacy object even when newer
	// timestamped runs of that day exist. During the transition every such day
	// has both, and the legacy one is the older copy: the exact case the new
	// scheme exists to stop an operator from being handed.
	if _, err := time.Parse(dateLayout, want); err == nil {
		for _, o := range objs { // newest first
			if o.Day() == want {
				return o.Key, nil
			}
		}
		return "", fmt.Errorf("restore: no backup for %s under prefix %q", want, prefix)
	}
	// Otherwise it is a full stem, pinning one specific run.
	exact := prefix + want + objectSuffix
	for _, o := range objs {
		if o.Key == exact {
			return o.Key, nil
		}
	}
	return "", fmt.Errorf("restore: %q is neither a date (YYYY-MM-DD) nor a known backup stem", want)
}

// parseKeyDate extracts the moment a backup object is named for.
//
// Two shapes are accepted: the current "<prefix>YYYY-MM-DDTHHMMSSZ" and the
// legacy one-per-day "<prefix>YYYY-MM-DD", which resolves to midnight UTC so
// it still sorts and prunes alongside the others. legacy reports which.
func parseKeyDate(key string) (t time.Time, legacy bool, ok bool) {
	base := path.Base(key)
	if !strings.HasSuffix(base, objectSuffix) {
		return time.Time{}, false, false
	}
	stamp := strings.TrimSuffix(base, objectSuffix)
	if t, err := time.Parse(stampLayout, stamp); err == nil {
		return t.UTC(), false, true
	}
	if t, err := time.Parse(dateLayout, stamp); err == nil {
		return t.UTC(), true, true
	}
	return time.Time{}, false, false
}
