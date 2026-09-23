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

func TestBuildConfigRejectsOutputFileOutsideSandbox(t *testing.T) {
	setTemplateDir(t)
	executionID := "deny-" + t.Name()
	setLocalFileAccess(executionID, false)
	outsidePath := filepath.Join(t.TempDir(), "ticket.ccache")

	t.Run("request output_file", func(t *testing.T) {
		req := validTicketRequest()
		req.OutputFile = outsidePath

		_, err := buildConfig(executionID, req, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "-allow-local-file-access is not enabled")
	})

	t.Run("silver outputFile argument", func(t *testing.T) {
		_, err := buildConfig(executionID, validTicketRequest(), outsidePath)
		require.Error(t, err)
		require.Contains(t, err.Error(), "-allow-local-file-access is not enabled")
	})
}

func TestBuildConfigAllowsOutputFileInsideSandbox(t *testing.T) {
	templatesDir := setTemplateDir(t)
	executionID := "sandbox-" + t.Name()
	setLocalFileAccess(executionID, false)

	outputPath := filepath.Join(templatesDir, "generated", "ticket.ccache")
	req := validTicketRequest()
	req.OutputFile = outputPath

	cfg, err := buildConfig(executionID, req, "")
	require.NoError(t, err)
	require.Equal(t, outputPath, cfg.OutputFile)
}

func TestBuildConfigNormalizesRelativeOutputFileInsideSandbox(t *testing.T) {
	templatesDir := setTemplateDir(t)
	executionID := "relative-" + t.Name()
	setLocalFileAccess(executionID, false)

	cfg, err := buildConfig(executionID, validTicketRequest(), filepath.Join("generated", "ticket.ccache"))
	require.NoError(t, err)
	require.Equal(t, filepath.Join(templatesDir, "generated", "ticket.ccache"), cfg.OutputFile)
}

func TestBuildConfigAllowsOutputFileWhenLocalFileAccessEnabled(t *testing.T) {
	setTemplateDir(t)
	executionID := "allow-" + t.Name()
	setLocalFileAccess(executionID, true)
	outsidePath := filepath.Join(t.TempDir(), "ticket.ccache")

	cfg, err := buildConfig(executionID, validTicketRequest(), outsidePath)
	require.NoError(t, err)
	require.Equal(t, outsidePath, cfg.OutputFile)
}

func TestCreateGoldenTicketRejectsOutputFileOutsideSandboxFromRuntime(t *testing.T) {
	setTemplateDir(t)
	executionID := "runtime-" + t.Name()
	setLocalFileAccess(executionID, false)

	runtime := goja.New()
	runtime.SetContextValue("executionId", executionID)

	req := validTicketRequest()
	req.OutputFile = filepath.Join(t.TempDir(), "ticket.ccache")

	var panicValue any
	func() {
		defer func() {
			panicValue = recover()
		}()

		CreateGoldenTicket(goja.FunctionCall{
			Arguments: []goja.Value{runtime.ToValue(req)},
		}, runtime)
	}()

	require.NotNil(t, panicValue)
	require.Contains(t, fmt.Sprint(panicValue), "-allow-local-file-access is not enabled")
}

func TestCreateSilverTicketDoesNotWriteDefaultCCache(t *testing.T) {
	setTemplateDir(t)
	executionID := "silver-" + t.Name()
	setLocalFileAccess(executionID, false)

	cwd := t.TempDir()
	t.Chdir(cwd)

	ticket, err := createSilverTicket(executionID, validTicketRequest(), "")
	require.NoError(t, err)
	require.Equal(t, "-", ticket.OutputFile)

	_, err = os.Stat(filepath.Join(cwd, "Administrator.ccache"))
	require.ErrorIs(t, err, os.ErrNotExist)
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
