package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// All CLI state readers/writers share this OS lock. The URI resolver releases it
// during network work and checks its snapshot under the lock before committing.
// The lock is beside the state root so a cold doctor creates no identity or state
// directory. Its location must not depend on each client's TMPDIR. Never unlink
// a lock file: waiters may hold it open.
func acquireConsumerState(ctx context.Context) (func(), error) {
	root, err := filepath.Abs(Home())
	if err != nil {
		return nil, err
	}
	parent, suffix := root, ""
	for {
		resolved, err := filepath.EvalSymlinks(parent)
		if err == nil {
			root = filepath.Join(resolved, suffix)
			break
		}
		if !os.IsNotExist(err) || filepath.Dir(parent) == parent {
			return nil, err
		}
		suffix = filepath.Join(filepath.Base(parent), suffix)
		parent = filepath.Dir(parent)
	}
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(filepath.Dir(root), fmt.Sprintf(".axela-state-%x.lock", sha256.Sum256([]byte(root))))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cannot coordinate local Axela state: %w", err)
	}
	info, statErr := file.Stat()
	link, linkErr := os.Lstat(path)
	if statErr != nil || linkErr != nil || !info.Mode().IsRegular() || link.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, link) {
		file.Close()
		return nil, fmt.Errorf("local Axela state lock is not a regular file")
	}
	for {
		locked, err := tryConsumerStateLock(file)
		if err != nil {
			file.Close()
			return nil, err
		}
		if locked {
			return func() { releaseConsumerStateLock(file); file.Close() }, nil
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			file.Close()
			return nil, fmt.Errorf("another Axela command is updating local state; retry %s doctor: %w", commandName(), ctx.Err())
		case <-timer.C:
		}
	}
}

func lockCLIState(command string) (func(), error) {
	switch command {
	case "init", "trust", "sync", "refresh", "connect", "doctor", "status", "statusline", "adopt", "diff", "hook", "attest", "report", "install", "publish", "catalog", "marketplace":
		timeout := 5 * time.Second
		if command == "statusline" {
			timeout = 100 * time.Millisecond
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return acquireConsumerState(ctx)
	default:
		// Subscribe owns its transaction boundary; demo owns an isolated state
		// directory. Help, lint, setup and version do not mutate subscription state.
		return func() {}, nil
	}
}
