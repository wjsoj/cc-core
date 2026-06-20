package backup

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// FileEntry is one member of the backup archive. Name is the path *inside*
// the tarball (kept relative and stable so Restore lays files back out
// predictably under the destination dir). SourcePath is the absolute path on
// disk to read the bytes from.
type FileEntry struct {
	Name       string
	SourcePath string
	Mode       os.FileMode
}

// writeTarGz streams a gzip-compressed tar of entries to w. Each entry's
// bytes are read from its SourcePath. Missing source files are an error —
// the caller is responsible for pre-filtering optional files.
func writeTarGz(w io.Writer, entries []FileEntry) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		if err := writeOne(tw, e); err != nil {
			return fmt.Errorf("archive %s: %w", e.Name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func writeOne(tw *tar.Writer, e FileEntry) error {
	f, err := os.Open(e.SourcePath)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	mode := e.Mode
	if mode == 0 {
		mode = info.Mode().Perm()
	}
	hdr := &tar.Header{
		Name:    filepath.ToSlash(e.Name),
		Mode:    int64(mode.Perm()),
		Size:    info.Size(),
		ModTime: info.ModTime(),
		Format:  tar.FormatPAX,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

// extractTarGz unpacks a gzip-compressed tar from r into destDir. Member
// names are sanitized against path traversal (no absolute paths, no "..")
// so a malformed/hostile archive can never write outside destDir.
func extractTarGz(r io.Reader, destDir string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	cleanDest, err := filepath.Abs(destDir)
	if err != nil {
		return err
	}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue // we only ever write regular files
		}
		target, err := safeJoin(cleanDest, hdr.Name)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		mode := os.FileMode(hdr.Mode).Perm()
		if mode == 0 {
			mode = 0o600
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
	}
}

// safeJoin joins name onto base, rejecting empty/absolute names and any name
// containing a ".." segment, then double-checking the result stays inside base.
func safeJoin(base, name string) (string, error) {
	slash := filepath.ToSlash(name)
	if slash == "" || slash == "." {
		return "", fmt.Errorf("archive: empty member name")
	}
	if strings.HasPrefix(slash, "/") || filepath.IsAbs(name) {
		return "", fmt.Errorf("archive: member %q is absolute", name)
	}
	for _, seg := range strings.Split(slash, "/") {
		if seg == ".." {
			return "", fmt.Errorf("archive: member %q contains ..", name)
		}
	}
	target := filepath.Join(base, filepath.FromSlash(slash))
	rel, err := filepath.Rel(base, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("archive: member %q escapes destination", name)
	}
	return target, nil
}
