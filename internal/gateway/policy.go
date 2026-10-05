package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sync"

	"github.com/bolaum/ghgw/internal/core"
	"github.com/bolaum/ghgw/internal/policyfile"
	"github.com/bolaum/ghgw/internal/store"
)

// policySource gives each request the policy in force: the policy file, read again when it
// changes, with the owners the store has credentials for, read on every request so that ghgw owner
// add and remove take effect at once.
type policySource struct {
	path  string
	store *store.Store
	log   *slog.Logger

	mu sync.Mutex
	// stamp and owners are what snap (or err) was built from.
	stamp  os.FileInfo
	owners []string
	snap   *snapshot
	err    error
}

// snapshot is the policy one request is decided with.
type snapshot struct {
	file   *policyfile.File
	policy *core.Policy
}

// current returns the policy in force. An error means there is none: the file is missing or
// invalid, and every request is denied until the admin fixes it. Keeping the previous policy
// instead would keep access the admin meant to remove.
func (s *policySource) current(ctx context.Context) (*snapshot, error) {
	list, err := s.store.Owners(ctx)
	if err != nil {
		return nil, err
	}
	owners := make([]string, len(list))
	for i, o := range list {
		owners[i] = o.Name
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// The file is checked before it is read, so a change after the check is seen next time.
	stamp, err := os.Stat(s.path)
	switch {
	case err != nil && s.stamp == nil && s.err != nil:
		// Still unreadable; logged already.
		return nil, s.err
	case err != nil:
		return nil, s.failed(nil, fmt.Errorf("read the policy file: %w", err))
	case s.stamp != nil && sameStamp(s.stamp, stamp) && slices.Equal(s.owners, owners):
		return s.snap, s.err
	}
	s.owners = owners
	pf, err := policyfile.Load(s.path)
	if err != nil {
		return nil, s.failed(stamp, err)
	}
	p, err := pf.Policy(owners)
	if err != nil {
		return nil, s.failed(stamp, err)
	}
	if s.err != nil {
		s.log.Info("the policy file is valid again", "path", s.path)
	}
	s.stamp, s.snap, s.err = stamp, &snapshot{file: pf, policy: p}, nil
	return s.snap, nil
}

// failed records that the file with stamp (nil when it is unreadable) gives no policy, and logs
// why. s.mu must be held.
func (s *policySource) failed(stamp os.FileInfo, err error) error {
	s.stamp, s.snap, s.err = stamp, nil, err
	s.log.Error("no valid policy: every request is denied until the policy file is fixed", "path", s.path, "error", err)
	return err
}

// sameStamp reports whether two stats show the same file content, as far as a stat can tell.
func sameStamp(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.ModTime().Equal(b.ModTime()) && a.Size() == b.Size() && a.Mode() == b.Mode()
}
