//go:build windows

package archive

import (
	"os"
	"path/filepath"
)

// hardLinkCount is unavailable through os.FileInfo on Windows. Reporting "unknown" keeps
// packaging working; the ACL model there makes the hard-link case far less relevant.
func hardLinkCount(os.FileInfo) (uint64, bool) { return 0, false }

func relativePosix(base, target string) (string, error) {
	relative, err := filepath.Rel(base, target)
	if err != nil {
		return "", failf(KindPath, "cannot resolve %q against %q: %v", target, base, err)
	}
	return filepath.ToSlash(relative), nil
}
