package utils

import (
	"fmt"
	"path"
	"strings"
)

// Joins two relative paths and handles trailing slash edgecase
func JoinURLPath(elem1 string, elem2 string) string {
	/*
		Trailing Slash EdgeCase
		Path.Join converts /test/ to /test
		this should be handled manually
	*/
	if elem2 == "" || elem2 == "/" || elem2 == "/?" {
		if elem2 == "" {
			return elem1
		} else {
			// check for extra slash
			if strings.HasSuffix(elem1, "/") && strings.HasPrefix(elem2, "/") {
				elem1 = strings.TrimRight(elem1, "/")
			}
			// merge and return
			return fmt.Sprintf("%v%v", elem1, elem2)
		}
	} else {
		if strings.HasPrefix(elem2, "?") {
			// path2 is parameter and not a url append and return
			return fmt.Sprintf("%v%v", elem1, elem2)
		}
		// Note:
		// path.Join implicitly calls path.Clean so any relative paths are filtered
		// if not encoded properly
		return path.Join(elem1, elem2)
	}

}
