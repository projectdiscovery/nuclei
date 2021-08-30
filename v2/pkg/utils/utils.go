package utils

import (
	"regexp"
	"strings"
)

func IsBlank(value string) bool {
	return strings.TrimSpace(value) == ""
}

func IsNotBlank(value string) bool {
	return !IsBlank(value)
}

func PlaceholderRegex(key string) *regexp.Regexp {
	return regexp.MustCompile(`((\{\{)|§)` + key + `((\}\})|§)`)
}
