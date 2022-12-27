package utils

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils/yaml"
	fileutil "github.com/projectdiscovery/utils/file"
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
func ReadFromPathOrURL(templatePath string, catalog catalog.Catalog) (data []byte, err error) {
	var reader io.Reader
	if IsURL(templatePath) {
		resp, err := http.Get(templatePath)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		reader = resp.Body
	} else {
		f, err := catalog.OpenFile(templatePath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		reader = f
	}

	data, err = io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	// pre-process directives only for local files
	if fileutil.FileExists(templatePath) {
		data, err = yaml.PreProcess(data)
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

// RemoveDuplicate removes the duplicates in a slice
func RemoveDuplicate[T string | int](sliceList []T) []T {
	allKeys := make(map[T]bool)
	list := []T{}
	for _, item := range sliceList {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

// ParseHostname returns hostname
func ParseHostname(inputURL string) string {
	/*
		currently if URL is scanme.sh/path or scanme.sh:443 i.e without protocol then
		url.Parse considers this as valid url but fails to parse hostname
		this can be handled by adding schema
	*/
	input, err := url.Parse(inputURL)
	if err != nil {
		return ""
	}
	if input.Host == "" {
		newinput, err := url.Parse("https://" + inputURL)
		if err != nil {
			return ""
		}
		return newinput.Host
	}
	return input.Host
}
