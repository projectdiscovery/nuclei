//go:build integration
// +build integration

package integration_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/utils/errkit"
	permissionutil "github.com/projectdiscovery/utils/permission"
)

func TestLoader(t *testing.T) {
	t.Run("RemoteTemplateList", func(t *testing.T) {
		server := newLoaderServer(t, "/template_list", fixturePath("loader/template-list.yaml"))

		configPath := writeAllowedRemoteConfig(t, server.Listener.Addr().String())
		results, err := testutils.RunNucleiBareArgsAndGetResults(suite.debug, nil,
			"-target", server.URL,
			"-template-url", server.URL+"/template_list",
			"-config", configPath,
		)
		if err != nil {
			t.Fatalf("expected remote template list to succeed: %v", err)
		}
		if err := expectResultsCount(results, 2); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("ExcludedTemplate", func(t *testing.T) {
		server := newLoaderServer(t, "", "")

		templatePath := fixturePath("loader/excluded-template.yaml")
		results, err := testutils.RunNucleiBareArgsAndGetResults(suite.debug, nil,
			"-target", server.URL,
			"-t", templatePath,
			"-include-templates", templatePath,
		)
		if err != nil {
			t.Fatalf("expected excluded template case to succeed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("RemoteTemplateListNotAllowed", func(t *testing.T) {
		server := newLoaderServer(t, "/template_list", fixturePath("loader/template-list.yaml"))

		_, err := testutils.RunNucleiBareArgsAndGetResults(suite.debug, nil,
			"-target", server.URL,
			"-template-url", server.URL+"/template_list",
		)
		if err == nil {
			t.Fatal("expected error for remote template list without allow-list config")
		}
	})

	t.Run("RemoteWorkflowList", func(t *testing.T) {
		server := newLoaderServer(t, "/workflow_list", fixturePath("loader/workflow-list.yaml"))

		configPath := writeAllowedRemoteConfig(t, server.Listener.Addr().String())
		results, err := testutils.RunNucleiBareArgsAndGetResults(suite.debug, nil,
			"-target", server.URL,
			"-workflow-url", server.URL+"/workflow_list",
			"-config", configPath,
		)
		if err != nil {
			t.Fatalf("expected remote workflow list to succeed: %v", err)
		}
		if err := expectResultsCount(results, 3); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("NonExistentTemplateList", func(t *testing.T) {
		server := newLoaderServer(t, "", "")

		configPath := writeAllowedRemoteConfig(t, server.Listener.Addr().String())
		_, err := testutils.RunNucleiBareArgsAndGetResults(suite.debug, nil,
			"-target", server.URL,
			"-template-url", server.URL+"/404",
			"-config", configPath,
		)
		if err == nil {
			t.Fatal("expected error for non-existing remote template list")
		}
	})

	t.Run("NonExistentWorkflowList", func(t *testing.T) {
		server := newLoaderServer(t, "", "")

		configPath := writeAllowedRemoteConfig(t, server.Listener.Addr().String())
		_, err := testutils.RunNucleiBareArgsAndGetResults(suite.debug, nil,
			"-target", server.URL,
			"-workflow-url", server.URL+"/404",
			"-config", configPath,
		)
		if err == nil {
			t.Fatal("expected error for non-existing remote workflow list")
		}
	})

	t.Run("LoadTemplateWithID", func(t *testing.T) {
		server := newLoaderServer(t, "", "")

		templateDir := t.TempDir()
		copyFixtureToDir(t, "library/test.yaml", templateDir)
		results, err := testutils.RunNucleiBareArgsAndGetResults(suite.debug, []string{"NUCLEI_TEMPLATES_DIR=" + templateDir},
			"-target", server.URL,
			"-id", "go-integration-test",
		)
		if err != nil {
			t.Fatalf("failed to load template with id: %v", errkit.Wrap(err, "load template with id"))
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})
}

func newLoaderServer(t *testing.T, listPath, listFixture string) *httptest.Server {
	t.Helper()

	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		_, _ = fmt.Fprint(w, "This is test matcher text")
		if strings.EqualFold(r.Header.Get("test"), "nuclei") {
			_, _ = fmt.Fprint(w, "This is test headers matcher text")
		}
	})
	if listPath != "" {
		router.GET(listPath, func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
			file, err := os.ReadFile(listFixture)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(file)
		})
	}

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return server
}

func writeAllowedRemoteConfig(t *testing.T, allowedAddress string) string {
	t.Helper()

	configPath := filepath.Join(t.TempDir(), "test-config.yaml")
	configData := []byte(`remote-template-domain: [ "` + allowedAddress + `" ]`)
	if err := os.WriteFile(configPath, configData, permissionutil.ConfigFilePermission); err != nil {
		t.Fatalf("failed to write remote template allow-list config: %v", err)
	}
	return configPath
}
