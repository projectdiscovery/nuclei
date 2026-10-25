package smb

import (
	"context"

	"github.com/projectdiscovery/nuclei/v3/pkg/js/libs/smbsession"
)

// ShareEntry is a single file or directory on an SMB share.
type ShareEntry = smbsession.Entry

// @memo
func listShares(ctx context.Context, executionId string, host string, port int, user string, password string) ([]string, error) {
	sess, err := smbsession.Dial(ctx, executionId, host, port, smbsession.Creds{User: user, Password: password})
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	return sess.ListShares()
}

// @memo
func listDir(ctx context.Context, executionId string, host string, port int, user string, password string, share string, dir string) ([]ShareEntry, error) {
	if err := smbsession.RequireShareName(share); err != nil {
		return nil, err
	}
	sess, err := smbsession.Dial(ctx, executionId, host, port, smbsession.Creds{User: user, Password: password})
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	return sess.ListDir(share, dir)
}

// @memo
func readFile(ctx context.Context, executionId string, host string, port int, user string, password string, share string, filePath string) (string, error) {
	if err := smbsession.RequireShareName(share); err != nil {
		return "", err
	}
	sess, err := smbsession.Dial(ctx, executionId, host, port, smbsession.Creds{User: user, Password: password})
	if err != nil {
		return "", err
	}
	defer sess.Close()
	return sess.ReadFile(share, filePath, smbsession.DefaultMaxReadBytes)
}

// @memo
func listTree(ctx context.Context, executionId string, host string, port int, user string, password string, share string, dir string) ([]ShareEntry, error) {
	if err := smbsession.RequireShareName(share); err != nil {
		return nil, err
	}
	sess, err := smbsession.Dial(ctx, executionId, host, port, smbsession.Creds{User: user, Password: password})
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	return sess.ListTree(share, dir, smbsession.DefaultMaxTreeDepth, smbsession.DefaultMaxTreeEntries)
}
