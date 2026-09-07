//go:build !windows

package archive

import (
	"os"
	"path/filepath"
	"syscall"
)

// hardLinkCount reports the link count when the platform exposes it. A file with more than
// one link can be mutated through another name after packaging. The path is unused here —
// the count comes from the stat already taken — and is what Windows needs.
func hardLinkCount(_ string, info os.FileInfo) (uint64, bool) {
	raw, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(raw.Nlink), true
}

func relativePosix(base, target string) (string, error) {
	relative, err := filepath.Rel(base, target)
	if err != nil {
		return "", failf(KindPath, "cannot resolve %q against %q: %v", target, base, err)
	}
	return filepath.ToSlash(relative), nil
}
