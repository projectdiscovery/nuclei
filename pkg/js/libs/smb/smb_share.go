package smb

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/js/libs/smbsession"
)

// ShareEntry is a single file or directory on an SMB share.
type ShareEntry = smbsession.Entry

// @memo
func listShares(ctx context.Context, executionId string, host string, port int, user string, password string) ([]string, error) {
	return listSharesWithOptions(ctx, executionId, SMBOptions{
		Host:     host,
		Port:     port,
		User:     user,
		Password: password,
	})
}

func listSharesWithOptions(ctx context.Context, executionId string, opts SMBOptions) ([]string, error) {
	if opts.Host == "" || opts.Port <= 0 {
		return nil, fmt.Errorf("invalid host or port")
	}

	timeout := 10 * time.Second
	if opts.Timeout > 0 {
		timeout = time.Duration(opts.Timeout) * time.Second
	}
	dialCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	hash := opts.Hash
	if i := strings.LastIndex(hash, ":"); i >= 0 {
		hash = hash[i+1:]
	}

	sess, err := smbsession.Dial(dialCtx, executionId, opts.Host, opts.Port, smbsession.Creds{
		User:     opts.User,
		Password: opts.Password,
		Domain:   opts.Domain,
		Hash:     hash,
	})
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
