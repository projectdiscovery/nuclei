package utils

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/projectdiscovery/fileutil"
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

func LoadFile(filename string) ([]string, error) {
	var items []string
	readfileChan, err := fileutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	for includeIdLine := range readfileChan {
		items = append(items, includeIdLine)
	}
	return items, nil
}

// IsURL tests a string to determine if it is a well-structured url or not.
func IsURL(input string) bool {
	_, err := url.ParseRequestURI(input)
	if err != nil {
		return false
	}

	u, err := url.Parse(input)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}

	return true
}

// ReadFromPathOrURL reads and returns the contents of a file or url.
func ReadFromPathOrURL(templatePath string) (data []byte, err error) {
	if IsURL(templatePath) {
		resp, err := http.Get(templatePath)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		data, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
	} else {
		f, err := os.Open(templatePath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		data, err = ioutil.ReadAll(f)
		if err != nil {
			return nil, err
		}
	}
	return
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
