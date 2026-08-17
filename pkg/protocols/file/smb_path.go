package file

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/js/libs/smbsession"
)

// SMBTarget is a parsed UNC or smb:// path suitable for the file protocol bridge.
//
// Accepted forms (issue #6142):
//
//	\\host\share\path\to\file
//	//host/share/path/to/file
//	smb://host/share/path/to/file
//	smb://user:pass@host/share/path
//	smb://domain;user:pass@host/share/path
type SMBTarget struct {
	Host     string
	Port     int
	Share    string
	Path     string // share-relative; "." for share root / directory listing
	User     string
	Password string
	Domain   string
}

// IsSMBPath reports whether input looks like a remote SMB target rather than a local path.
func IsSMBPath(input string) bool {
	input = strings.TrimSpace(input)
	if input == "" {
		return false
	}
	lower := strings.ToLower(input)
	if strings.HasPrefix(lower, "smb://") {
		return true
	}
	if strings.HasPrefix(input, `\\`) || strings.HasPrefix(input, "//") {
		return true
	}
	return false
}

// ParseSMBTarget parses an SMB UNC or smb:// URL into an SMBTarget.
func ParseSMBTarget(input string) (*SMBTarget, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("empty SMB path")
	}
	lower := strings.ToLower(input)
	if strings.HasPrefix(lower, "smb://") {
		return parseSMBURL(input)
	}
	if strings.HasPrefix(input, `\\`) || strings.HasPrefix(input, "//") {
		return parseUNC(input)
	}
	return nil, fmt.Errorf("not an SMB path: %q", input)
}

func parseSMBURL(raw string) (*SMBTarget, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse smb url: %w", err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("smb url missing host")
	}
	host := u.Hostname()
	port := 445
	if p := u.Port(); p != "" {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err == nil && n > 0 {
			port = n
		}
	}
	user, pass, domain := "", "", ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
		// domain;user form in username
		if i := strings.IndexByte(user, ';'); i >= 0 {
			domain = user[:i]
			user = user[i+1:]
		}
	}
	share, rel, err := splitSharePath(u.Path)
	if err != nil {
		return nil, err
	}
	return &SMBTarget{
		Host:     host,
		Port:     port,
		Share:    share,
		Path:     rel,
		User:     user,
		Password: pass,
		Domain:   domain,
	}, nil
}

func parseUNC(raw string) (*SMBTarget, error) {
	s := strings.ReplaceAll(raw, `\`, `/`)
	s = strings.TrimPrefix(s, "//")
	parts := strings.Split(s, "/")
	cleaned := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			cleaned = append(cleaned, p)
		}
	}
	if len(cleaned) < 2 {
		return nil, fmt.Errorf("UNC path requires \\\\host\\share: %q", raw)
	}
	host := cleaned[0]
	share := cleaned[1]
	rel := "."
	if len(cleaned) > 2 {
		rel = strings.Join(cleaned[2:], "/")
	}
	if err := smbsession.RequireShareName(share); err != nil {
		return nil, err
	}
	normalized, err := smbsession.NormalizeSharePath(rel)
	if err != nil {
		return nil, err
	}
	return &SMBTarget{Host: host, Port: 445, Share: share, Path: normalized}, nil
}

func splitSharePath(urlPath string) (share, rel string, err error) {
	urlPath = strings.Trim(urlPath, "/")
	if urlPath == "" {
		return "", "", fmt.Errorf("smb url missing share name")
	}
	parts := strings.SplitN(urlPath, "/", 2)
	share = parts[0]
	if err := smbsession.RequireShareName(share); err != nil {
		return "", "", err
	}
	rel = "."
	if len(parts) == 2 {
		rel = parts[1]
	}
	normalized, err := smbsession.NormalizeSharePath(rel)
	if err != nil {
		return "", "", err
	}
	return share, normalized, nil
}

// Display returns a stable UNC-like string for events/logs (never embeds password).
func (t *SMBTarget) Display() string {
	if t == nil {
		return ""
	}
	if t.Path == "" || t.Path == "." {
		return fmt.Sprintf(`\\%s\%s`, t.Host, t.Share)
	}
	p := strings.ReplaceAll(t.Path, `/`, `\`)
	return fmt.Sprintf(`\\%s\%s\%s`, t.Host, t.Share, p)
}
