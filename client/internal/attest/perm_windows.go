//go:build windows

package attest

import "os"

// assertOwnerOnly does nothing on Windows, and the reason matters.
//
// Go synthesizes FileMode there from the read-only attribute: a writable file always
// reports 0666 regardless of its ACL. Enforcing the POSIX check would reject every key on
// the platform while proving nothing, and reading 0666 as "world readable" would be a
// conclusion drawn from a value that carries no such information.
//
// The honest consequence is that key permissions are not checked on Windows. Protecting
// the key is the ACL's job there, and this tool does not inspect ACLs. That limitation is
// pinned by TestPrivateKeyPermissionsAreNotCheckedOnWindows rather than left in prose.
func assertOwnerOnly(string, os.FileInfo) error { return nil }
