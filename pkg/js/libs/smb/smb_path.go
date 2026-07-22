package smb

import (
	"fmt"
	"path"
	"strings"
)

const (
	// defaultMaxReadBytes caps how much of a remote file ReadFile will pull
	// into memory. Templates that need more should page with a dedicated
	// follow-up API rather than unbounded reads.
	defaultMaxReadBytes = 10 << 20 // 10 MiB

	// defaultMaxTreeDepth caps recursive ListTree walks.
	defaultMaxTreeDepth = 8

	// defaultMaxTreeEntries caps how many entries ListTree will collect.
	defaultMaxTreeEntries = 1024
)

// parseNTLMIdentity splits an optional DOMAIN\user (or user@domain) form into
// domain and username. Plain usernames return an empty domain.
func parseNTLMIdentity(user string) (domain, username string) {
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

// normalizeSharePath converts an SMB share-relative path to the form go-smb2
// expects (forward slashes, no leading slash, "." for share root).
func normalizeSharePath(p string) (string, error) {
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

func requireShareName(share string) error {
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
