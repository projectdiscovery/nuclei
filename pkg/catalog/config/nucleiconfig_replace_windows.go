package config

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var replaceFile = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReplaceFileW")

func replaceTemplatesConfigFile(temporaryPath, configFilePath string) error {
	temporary, err := windows.UTF16PtrFromString(temporaryPath)
	if err != nil {
		return err
	}

	target, err := windows.UTF16PtrFromString(configFilePath)
	if err != nil {
		return err
	}

	if _, err := os.Lstat(configFilePath); err != nil {
		if !os.IsNotExist(err) {
			return err
		}

		return windows.MoveFileEx(temporary, target, windows.MOVEFILE_WRITE_THROUGH)
	}

	replaced, _, callErr := replaceFile.Call(
		uintptr(unsafe.Pointer(target)),
		uintptr(unsafe.Pointer(temporary)),
		0,
		0,
		0,
		0,
	)
	if replaced != 0 {
		return nil
	}
	if errors.Is(callErr, windows.ERROR_FILE_NOT_FOUND) {
		return windows.MoveFileEx(temporary, target, windows.MOVEFILE_WRITE_THROUGH)
	}

	return callErr
}
