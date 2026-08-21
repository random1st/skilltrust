//go:build !windows

package attest

import (
	"fmt"
	"os"
)

// assertOwnerOnly refuses a signing key any other account can read. A key with loose
// permissions is a key anything running as another user on the machine can borrow, and the
// signature it produces is indistinguishable from a legitimate one.
func assertOwnerOnly(path string, info os.FileInfo) error {
	if permissions := info.Mode().Perm(); permissions&0o077 != 0 {
		return fmt.Errorf("%s is readable beyond its owner (%04o); "+
			"chmod 600 it before signing anything", path, permissions)
	}
	return nil
}
