package file

import (
	"context"
	"fmt"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/js/libs/smbsession"
)

func (request *Request) resolveSMBCreds(target *SMBTarget) smbsession.Creds {
	creds := smbsession.Creds{
		User:     request.SMBUser,
		Password: request.SMBPassword,
		Domain:   request.SMBDomain,
		Hash:     request.SMBHash,
	}
	if target.User != "" {
		creds.User = target.User
	}
	if target.Password != "" {
		creds.Password = target.Password
	}
	if target.Domain != "" {
		creds.Domain = target.Domain
	}
	if creds.Domain == "" && creds.User != "" {
		d, u := smbsession.ParseIdentity(creds.User)
		if d != "" {
			creds.Domain = d
			creds.User = u
		}
	}
	return creds
}

func (request *Request) smbPort(target *SMBTarget) int {
	if request.SMBPort > 0 {
		return request.SMBPort
	}
	if target.Port > 0 {
		return target.Port
	}
	return 445
}

func (request *Request) executionID() string {
	if request.options != nil && request.options.Options != nil {
		return request.options.Options.ExecutionId
	}
	return ""
}

// enumerateSMBInputs expands an SMB target into concrete file display paths.
//
// Example template usage:
//
//	id: smb-secrets-scan
//	file:
//	  - extensions: [all]
//	    smb-user: auditor
//	    smb-password: secret
//	# nuclei -t tmpl.yaml -target 'smb://fs01/backup/'
//	# or -target '\\fs01\backup\creds.txt'
func (request *Request) enumerateSMBInputs(ctx context.Context, input string, callback func(string)) error {
	target, err := ParseSMBTarget(input)
	if err != nil {
		return err
	}

	// Single-file targets: no dial needed for expansion (readSMBFile dials later).
	if !isDirectorySMBTarget(input) {
		callback(target.Display())
		return nil
	}

	execID := request.executionID()
	if execID == "" {
		return fmt.Errorf("smb file target requires an initialized execution id")
	}
	sess, err := smbsession.Dial(ctx, execID, target.Host, request.smbPort(target), request.resolveSMBCreds(target))
	if err != nil {
		return err
	}
	defer sess.Close()

	if request.NoRecursive {
		entries, err := sess.ListDir(target.Share, target.Path)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.IsDir {
				continue
			}
			child := *target
			child.Path = e.Name
			callback(child.Display())
		}
		return nil
	}

	entries, err := sess.ListTree(target.Share, target.Path, smbsession.DefaultMaxTreeDepth, smbsession.DefaultMaxTreeEntries)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir {
			continue
		}
		child := *target
		child.Path = e.Name
		callback(child.Display())
	}
	return nil
}

func (request *Request) readSMBFile(ctx context.Context, displayPath string) (string, error) {
	target, err := ParseSMBTarget(displayPath)
	if err != nil {
		return "", err
	}
	if target.Path == "." || isDirectorySMBTarget(displayPath) {
		return "", fmt.Errorf("smb path is a directory, not a file: %s", displayPath)
	}
	execID := request.executionID()
	if execID == "" {
		return "", fmt.Errorf("smb file target requires an initialized execution id")
	}
	sess, err := smbsession.Dial(ctx, execID, target.Host, request.smbPort(target), request.resolveSMBCreds(target))
	if err != nil {
		return "", err
	}
	defer sess.Close()
	maxBytes := request.maxSize
	if maxBytes <= 0 {
		maxBytes = smbsession.DefaultMaxReadBytes
	}
	return sess.ReadFile(target.Share, target.Path, maxBytes)
}

// isDirectorySMBTarget reports whether the path refers to a share root / dir listing.
func isDirectorySMBTarget(input string) bool {
	t, err := ParseSMBTarget(input)
	if err != nil {
		return false
	}
	return t.Path == "." || strings.HasSuffix(strings.TrimSpace(input), "/") || strings.HasSuffix(strings.TrimSpace(input), `\`)
}
