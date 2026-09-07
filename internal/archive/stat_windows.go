//go:build windows

package archive

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// hardLinkCount asks Windows directly. os.FileInfo cannot answer it there — Sys() gives
// Win32FileAttributeData, which has no link count — so this used to report "unknown" and
// a hard-linked file was packaged in silence. That is the one case the check exists for:
// a file with a second name can be rewritten through it after packaging, so the bytes
// somebody signed and the bytes on disk stop being the same thing without any of it
// touching the packaged path.
//
// A file that cannot be opened is reported as unknown rather than as an error: the caller
// has already stat'ed it, and refusing to package a tree because one file was momentarily
// locked would be a worse failure than the one this prevents.
func hardLinkCount(path string, _ os.FileInfo) (uint64, bool) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, false
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, false
	}
	defer windows.CloseHandle(handle)

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return 0, false
	}
	return uint64(info.NumberOfLinks), true
}

func relativePosix(base, target string) (string, error) {
	relative, err := filepath.Rel(base, target)
	if err != nil {
		return "", failf(KindPath, "cannot resolve %q against %q: %v", target, base, err)
	}
	return filepath.ToSlash(relative), nil
}
