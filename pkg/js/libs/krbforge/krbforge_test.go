package krbforge

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestCreateTicketDefaultOutput(t *testing.T) {
	for _, golden := range []bool{true, false} {
		for _, location := range []string{"sandbox", "outside denied", "outside allowed"} {
			t.Run(fmt.Sprintf("golden=%v/%s", golden, location), func(t *testing.T) {
				templatesDir := setTemplateDir(t)
				cwd := templatesDir
				if location != "sandbox" {
					cwd = t.TempDir()
				}
				t.Chdir(cwd)
				executionID := t.Name()
				setLocalFileAccess(executionID, location == "outside allowed")

				req := validTicketRequest()
				// goimpacket replaces slashes in SPN-style usernames with dots.
				req.Username = "service/http"
				var ticket *Ticket
				var err error
				if golden {
					req.SPN = ""
					ticket, err = createGoldenTicket(executionID, req)
				} else {
					ticket, err = createSilverTicket(executionID, req, "")
				}
				filename := "service.http.ccache"
				if location == "outside denied" {
					require.ErrorContains(t, err, "outside nuclei-template directory")
					require.Nil(t, ticket)
					_, err = os.Stat(filepath.Join(cwd, filename))
					require.ErrorIs(t, err, os.ErrNotExist)
					return
				}

				require.NoError(t, err)
				require.Equal(t, filename, ticket.OutputFile)
				require.NotEmpty(t, ticket.HexTicket)
				require.NotEmpty(t, ticket.HexKey)
				body, err := os.ReadFile(filepath.Join(cwd, ticket.OutputFile))
				require.NoError(t, err)
				require.NotEmpty(t, body)
			})
		}
	}
}

func TestCreateTicketRejectsUnsupportedOutput(t *testing.T) {
	cwd := setTemplateDir(t)
	t.Chdir(cwd)
	executionID := t.Name()
	setLocalFileAccess(executionID, true)

	for _, output := range []string{"-", "custom.ccache", filepath.Join(cwd, "custom.ccache")} {
		for _, method := range []string{"golden request", "silver request", "silver argument"} {
			t.Run(method+"/"+output, func(t *testing.T) {
				req := validTicketRequest()
				var ticket *Ticket
				var err error
				switch method {
				case "golden request":
					req.OutputFile = output
					ticket, err = createGoldenTicket(executionID, req)
				case "silver request":
					req.OutputFile = output
					ticket, err = createSilverTicket(executionID, req, "")
				case "silver argument":
					ticket, err = createSilverTicket(executionID, req, output)
				}
				require.ErrorContains(t, err, "custom output paths and in-memory ticket generation are not supported")
				require.Nil(t, ticket)
				files, err := os.ReadDir(cwd)
				require.NoError(t, err)
				require.Empty(t, files)
			})
		}
	}
}

func TestCreateTicketReportsWriteFailure(t *testing.T) {
	cwd := setTemplateDir(t)
	t.Chdir(cwd)
	executionID := t.Name()
	setLocalFileAccess(executionID, false)
	require.NoError(t, os.Mkdir(filepath.Join(cwd, "Administrator.ccache"), 0700))

	ticket, err := createGoldenTicket(executionID, validTicketRequest())
	require.ErrorContains(t, err, "failed to save ccache")
	require.Nil(t, ticket)
}

func TestCreateTicketRejectsDefaultOutputSymlink(t *testing.T) {
	cwd := setTemplateDir(t)
	t.Chdir(cwd)
	executionID := t.Name()
	setLocalFileAccess(executionID, false)
	outside := filepath.Join(t.TempDir(), "ticket.ccache")
	require.NoError(t, os.WriteFile(outside, []byte("unchanged"), 0600))
	if err := os.Symlink(outside, filepath.Join(cwd, "Administrator.ccache")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	ticket, err := createGoldenTicket(executionID, validTicketRequest())
	require.ErrorContains(t, err, "outside nuclei-template directory")
	require.Nil(t, ticket)
	body, err := os.ReadFile(outside)
	require.NoError(t, err)
	require.Equal(t, "unchanged", string(body))
}

func TestCreateTicketRejectsDefaultOutputHardLink(t *testing.T) {
	cwd := setTemplateDir(t)
	t.Chdir(cwd)
	executionID := t.Name()
	setLocalFileAccess(executionID, false)
	outside := filepath.Join(t.TempDir(), "ticket.ccache")
	require.NoError(t, os.WriteFile(outside, []byte("unchanged"), 0600))
	if err := os.Link(outside, filepath.Join(cwd, "Administrator.ccache")); err != nil {
		t.Skipf("hard link unavailable: %v", err)
	}

	ticket, err := createGoldenTicket(executionID, validTicketRequest())
	require.ErrorContains(t, err, "hard link")
	require.Nil(t, ticket)
	body, err := os.ReadFile(outside)
	require.NoError(t, err)
	require.Equal(t, "unchanged", string(body))
}

func TestCreateGoldenTicketDeniesDefaultOutputFromRuntime(t *testing.T) {
	setTemplateDir(t)
	cwd := t.TempDir()
	t.Chdir(cwd)
	executionID := t.Name()
	setLocalFileAccess(executionID, false)

	runtime := goja.New()
	runtime.SetContextValue("executionId", executionID)
	req := validTicketRequest()

	var panicValue any
	func() {
		defer func() { panicValue = recover() }()
		CreateGoldenTicket(goja.FunctionCall{
			Arguments: []goja.Value{runtime.ToValue(req)},
		}, runtime)
	}()

	require.NotNil(t, panicValue)
	require.Contains(t, fmt.Sprint(panicValue), "outside nuclei-template directory")
	_, err := os.Stat(filepath.Join(cwd, req.Username+".ccache"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestBuildConfigPreservesIdentity(t *testing.T) {
	t.Chdir(setTemplateDir(t))
	executionID := t.Name()
	setLocalFileAccess(executionID, false)
	req := validTicketRequest()
	req.Username = "service/http"
	cfg, err := buildConfig(executionID, req, "")
	require.NoError(t, err)
	require.Equal(t, req.Username, cfg.Username)
	require.Equal(t, req.Domain, cfg.Domain)
}

func setTemplateDir(t *testing.T) string {
	t.Helper()
	templatesDir := t.TempDir()
	originalTemplatesDir := config.DefaultConfig.TemplatesDirectory
	config.DefaultConfig.SetTemplatesDir(templatesDir)
	t.Cleanup(func() {
		config.DefaultConfig.SetTemplatesDir(originalTemplatesDir)
	})
	return templatesDir
}

func setLocalFileAccess(executionID string, allowed bool) {
	protocolstate.SetLfaAllowed(&types.Options{
		ExecutionId:          executionID,
		AllowLocalFileAccess: allowed,
	})
}

func validTicketRequest() TicketRequest {
	return TicketRequest{
		Username:  "Administrator",
		Domain:    "acme.local",
		DomainSID: "S-1-5-21-1004336348-1177238915-682003330",
		NTHash:    "31d6cfe0d16ae931b73c59d7e0c089c0",
		SPN:       "cifs/server01.acme.local",
	}
}
