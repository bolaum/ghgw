package store

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func wantErr(t *testing.T, err error, kind error, contains string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want one containing %q", contains)
	}
	if kind != nil && !errors.Is(err, kind) {
		t.Errorf("error = %v, want it to match %v", err, kind)
	}
	if !strings.Contains(err.Error(), contains) {
		t.Errorf("error = %v, want it to contain %q", err, contains)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fakeInfo is a FileInfo with a chosen mode and owner.
type fakeInfo struct {
	mode fs.FileMode
	uid  uint32
}

func (f fakeInfo) Name() string       { return "f" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

func TestCheckPrivate(t *testing.T) {
	const uid = 1000
	tests := []struct {
		name    string
		info    fakeInfo
		wantDir bool
		want    string // empty: accepted
	}{
		{name: "private file", info: fakeInfo{mode: 0o600, uid: uid}},
		{name: "read-only file", info: fakeInfo{mode: 0o400, uid: uid}},
		{name: "private directory", info: fakeInfo{mode: fs.ModeDir | 0o700, uid: uid}, wantDir: true},
		{name: "file of another user", info: fakeInfo{mode: 0o600, uid: 1001}, want: "owned by uid 1001, not by the user ghgw runs as (uid 1000)"},
		{name: "file of root", info: fakeInfo{mode: 0o600, uid: 0}, want: "owned by uid 0"},
		{name: "directory of another user", info: fakeInfo{mode: fs.ModeDir | 0o700, uid: 1001}, wantDir: true, want: "owned by uid 1001"},
		{name: "group-writable file", info: fakeInfo{mode: 0o620, uid: uid}, want: "mode 0620"},
		{name: "world-executable directory", info: fakeInfo{mode: fs.ModeDir | 0o701, uid: uid}, wantDir: true, want: "chmod 700"},
		{name: "file where a directory is expected", info: fakeInfo{mode: 0o700, uid: uid}, wantDir: true, want: "is not a directory"},
		{name: "directory where a file is expected", info: fakeInfo{mode: fs.ModeDir | 0o700, uid: uid}, want: "is not a regular file"},
		{name: "socket", info: fakeInfo{mode: fs.ModeSocket | 0o600, uid: uid}, want: "is not a regular file"},
		{name: "symbolic link", info: fakeInfo{mode: fs.ModeSymlink | 0o777, uid: uid}, want: "is a symbolic link"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkPrivate("/state/f", tt.info, tt.wantDir, uid)
			if tt.want == "" {
				if err != nil {
					t.Errorf("checkPrivate() error = %v, want nil", err)
				}
				return
			}
			wantErr(t, err, nil, tt.want)
		})
	}
}

func TestCreatePrivateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := createPrivateFile(path, []byte("first")); err != nil {
		t.Fatalf("createPrivateFile() error = %v", err)
	}
	err := createPrivateFile(path, []byte("second"))
	if !errors.Is(err, fs.ErrExist) {
		t.Errorf("createPrivateFile(existing) error = %v, want fs.ErrExist", err)
	}
	if got := readFile(t, path); string(got) != "first" {
		t.Errorf("content = %q, want the first write kept", got)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %04o, want 0600", perm)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("directory holds %d entries, want only the file (no temporary file left)", len(entries))
	}
}

func TestReadPrivateFileBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := createPrivateFile(path, bytes.Repeat([]byte("a"), maxSmallFile+1)); err != nil {
		t.Fatal(err)
	}
	_, err := readPrivateFile(path)
	wantErr(t, err, nil, "larger than 1024 bytes")
}

func TestReadPrivateFileDoesNotBlockOnFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readPrivateFile(path)
		done <- err
	}()
	select {
	case err := <-done:
		wantErr(t, err, nil, "is not a regular file")
	case <-time.After(5 * time.Second):
		t.Fatal("readPrivateFile blocked on a FIFO")
	}
}
