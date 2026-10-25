package smbsession

import (
	"fmt"
	"path"
	"strings"
)

// ParseIdentity splits DOMAIN\user, domain/user, or user@domain into domain and username.
func ParseIdentity(user string) (domain, username string) {
	user = strings.TrimSpace(user)
	if user == "" {
		return "", ""
	}
	if i := strings.IndexByte(user, '\\'); i >= 0 {
		return user[:i], user[i+1:]
	}
	if i := strings.IndexByte(user, '/'); i >= 0 {
		return user[:i], user[i+1:]
	}
	if i := strings.LastIndexByte(user, '@'); i > 0 {
		return user[i+1:], user[:i]
	}
	return "", user
}

// NormalizeSharePath converts an SMB share-relative path to a clean form
// (forward slashes, no leading slash, "." for share root). Rejects ".." escapes.
func NormalizeSharePath(p string) (string, error) {
	p = strings.TrimSpace(p)
	p = strings.ReplaceAll(p, `\`, `/`)
	p = strings.Trim(p, `/`)
	if p == "" || p == "." {
		return ".", nil
	}
	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("share path contains NUL")
	}
	clean := path.Clean(p)
	clean = strings.TrimPrefix(clean, "/")
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("share path escapes share root: %q", p)
	}
	if clean == "." {
		return ".", nil
	}
	return clean, nil
}

// RequireShareName validates a share name (no path separators).
func RequireShareName(share string) error {
	share = strings.TrimSpace(share)
	if share == "" {
		return fmt.Errorf("share name cannot be empty")
	}
	if strings.ContainsAny(share, `/\`) {
		return fmt.Errorf("share name must not contain path separators: %q", share)
	}
	if strings.ContainsRune(share, 0) {
		return fmt.Errorf("share name contains NUL")
	}
	return nil
}
