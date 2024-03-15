package utils

import (
	"errors"
	"io"
	"net/url"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/retryablehttp-go"
)

func IsBlank(value string) bool {
	return strings.TrimSpace(value) == ""
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

// IsURL tests a string to determine if it is a well-structured url or not.
func IsURL(input string) bool {
	u, err := url.Parse(input)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// ReadFromPathOrURL reads and returns the contents of a file or url.
func ReaderFromPathOrURL(templatePath string, catalog catalog.Catalog) (io.ReadCloser, error) {
	if IsURL(templatePath) {
		resp, err := retryablehttp.DefaultClient().Get(templatePath)
		if err != nil {
			return nil, err
		}
		return resp.Body, nil
	} else {
		f, err := catalog.OpenFile(templatePath)
		if err != nil {
			return nil, err
		}
		return f, nil
	}
}

// StringSliceContains checks if a string slice contains a string.
func StringSliceContains(slice []string, item string) bool {
	for _, i := range slice {
		if strings.EqualFold(i, item) {
			return true
		}
	}
	return false
}
