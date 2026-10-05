package store

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// The files of the state directory.
const (
	dbFile         = "ghgw.db"
	masterKeyFile  = "master.key"
	adminTokenFile = "admin-token"
)

// stateFiles lists every file ghgw keeps in the state directory, SQLite's side files included,
// so all of them are checked at start.
var stateFiles = []string{
	dbFile, dbFile + "-wal", dbFile + "-shm", dbFile + "-journal",
	masterKeyFile, adminTokenFile,
}

// maxSmallFile bounds what is read from the master key and admin token files.
const maxSmallFile = 1024

// prepareDir creates the state directory when it is missing (mode 0700, parents too) and checks
// that it and the files ghgw keeps in it are private to the current user. Only the state
// directory and its files are checked, not its parents.
func prepareDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create the state directory: %w", err)
	}
	uid := os.Geteuid()
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("state directory: %w", err)
	}
	if err := checkPrivate(dir, fi, true, uid); err != nil {
		return err
	}
	for _, name := range stateFiles {
		path := filepath.Join(dir, name)
		fi, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("state file: %w", err)
		}
		if err := checkPrivate(path, fi, false, uid); err != nil {
			return err
		}
	}
	return nil
}

// checkPrivate checks that fi (of path) is a directory (wantDir) or a regular file, not a
// symbolic link, owned by uid and with no permission for group or others.
func checkPrivate(path string, fi fs.FileInfo, wantDir bool, uid int) error {
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("%s is a symbolic link; ghgw refuses to follow links in its state: use the real path", path)
	case wantDir && !fi.IsDir():
		return fmt.Errorf("state directory %s is not a directory", path)
	case !wantDir && !fi.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file; remove it", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read the file owner", path)
	}
	if int(st.Uid) != uid {
		return fmt.Errorf("%s is owned by uid %d, not by the user ghgw runs as (uid %d); fix the owner or run ghgw as that user", path, st.Uid, uid)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		want := "600"
		if wantDir {
			want = "700"
		}
		return fmt.Errorf("%s is accessible by group or others (mode %04o); run chmod %s %s", path, perm, want, path)
	}
	return nil
}

// readPrivateFile reads a small file that must be private to the current user. The checks run on
// the opened file, so the file cannot be swapped between check and read. A missing file is
// reported as fs.ErrNotExist.
func readPrivateFile(path string) ([]byte, error) {
	// O_NONBLOCK: a FIFO planted after the directory check cannot block the open.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s is a symbolic link; ghgw refuses to follow links in its state: use the real path", path)
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := checkPrivate(path, fi, false, os.Geteuid()); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSmallFile+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxSmallFile {
		return nil, fmt.Errorf("%s is larger than %d bytes; it is not a file ghgw wrote", path, maxSmallFile)
	}
	return data, nil
}

// createPrivateFile creates path with data and mode 0600, so the file is never readable by others,
// not even for a moment. It never replaces an existing file (fs.ErrExist). Callers hold the
// database write lock, so no other ghgw reads the file before it is complete; a crash while
// writing leaves a partial file, which the next start reports as malformed.
func createPrivateFile(path string, data []byte) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(path)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
