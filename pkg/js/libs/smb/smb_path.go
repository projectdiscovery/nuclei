package smb

import "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/smbsession"

const (
	defaultMaxReadBytes   = smbsession.DefaultMaxReadBytes
	defaultMaxTreeDepth   = smbsession.DefaultMaxTreeDepth
	defaultMaxTreeEntries = smbsession.DefaultMaxTreeEntries
)

func parseNTLMIdentity(user string) (domain, username string) {
	return smbsession.ParseIdentity(user)
}

func normalizeSharePath(p string) (string, error) {
	return smbsession.NormalizeSharePath(p)
}

func requireShareName(share string) error {
	return smbsession.RequireShareName(share)
}
