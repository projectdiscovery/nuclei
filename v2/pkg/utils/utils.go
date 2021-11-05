package utils

import (
	"errors"
	"strings"
)

func IsBlank(value string) bool {
	return strings.TrimSpace(value) == ""
}

func IsNotBlank(value string) bool {
	return !IsBlank(value)
}

func UnwrapError(err error) error {
	for { // get the last wrapped error
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			break
		}
		err = unwrapped
	}
	return err
}
