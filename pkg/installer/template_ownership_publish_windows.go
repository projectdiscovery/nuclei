//go:build windows

package installer

import (
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

type templateRestoreRenameInformation struct {
	replaceIfExists uint32
	rootDirectory   windows.Handle
	fileNameLength  uint32
	fileName        [1]uint16
}

func renameTemplateRestoreNoReplace(root *os.Root, temporaryPath, retiredPath string) error {
	sourceDirectory, err := root.Open(filepath.Dir(temporaryPath))
	if err != nil {
		return err
	}
	defer func() { _ = sourceDirectory.Close() }()

	destinationDirectory, err := root.Open(filepath.Dir(retiredPath))
	if err != nil {
		return err
	}
	defer func() { _ = destinationDirectory.Close() }()

	objectName, err := windows.NewNTUnicodeString(filepath.Base(temporaryPath))
	if err != nil {
		return err
	}

	attributes := &windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: windows.Handle(sourceDirectory.Fd()),
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE,
	}

	var source windows.Handle
	var status windows.IO_STATUS_BLOCK

	if err := windows.NtCreateFile(
		&source,
		windows.SYNCHRONIZE|windows.DELETE,
		attributes,
		&status,
		nil,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN,
		windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	); err != nil {
		return err
	}
	defer windows.CloseHandle(source)

	targetName, err := windows.UTF16FromString(filepath.Base(retiredPath))
	if err != nil {
		return err
	}

	targetNameLength := (len(targetName) - 1) * 2

	var header templateRestoreRenameInformation

	buffer := make([]byte, int(unsafe.Offsetof(header.fileName))+targetNameLength)
	info := (*templateRestoreRenameInformation)(unsafe.Pointer(&buffer[0]))
	info.rootDirectory = windows.Handle(destinationDirectory.Fd())
	info.fileNameLength = uint32(targetNameLength)
	copy((*[windows.MAX_LONG_PATH]uint16)(unsafe.Pointer(&info.fileName[0]))[:targetNameLength/2:targetNameLength/2], targetName)

	return windows.NtSetInformationFile(source, &status, &buffer[0], uint32(len(buffer)), windows.FileRenameInformation)
}
