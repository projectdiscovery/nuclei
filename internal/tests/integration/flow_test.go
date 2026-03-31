//go:build integration
// +build integration

package integration_test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
)

func TestFlow(t *testing.T) {
	t.Run("ConditionalFlow", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("flow/conditional-flow.yaml", "cloud.projectdiscovery.io", suite.debug)
		if err != nil {
			t.Fatalf("conditional flow request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("ConditionalFlowNegative", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("flow/conditional-flow-negative.yaml", "scanme.sh", suite.debug)
		if err != nil {
			t.Fatalf("conditional negative flow request failed: %v", err)
		}
		if err := expectResultsCount(results, 0); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("IterateValuesFlow", func(t *testing.T) {
		router := httprouter.New()
		testEmails := []string{"secrets@scanme.sh", "superadmin@scanme.sh"}
		router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, testEmails)
		})
		router.GET("/user/"+getBase64(testEmails[0]), func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Welcome ! This is test matcher text"))
		})
		router.GET("/user/"+getBase64(testEmails[1]), func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Welcome ! This is test matcher text"))
		})
		server := httptest.NewServer(router)
		defer server.Close()

		results, err := testutils.RunNucleiTemplateAndGetResults("flow/iterate-values-flow.yaml", server.URL, suite.debug)
		if err != nil {
			t.Fatalf("iterate values flow request failed: %v", err)
		}
		if err := expectResultsCount(results, 2); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("IterateOneValueFlow", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("flow/iterate-one-value-flow.yaml", "https://scanme.sh", suite.debug)
		if err != nil {
			t.Fatalf("iterate one value flow request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("DNSNSProbe", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("flow/dns-ns-probe.yaml", "oast.fun", suite.debug)
		if err != nil {
			t.Fatalf("dns ns probe flow request failed: %v", err)
		}
		if err := expectResultsCount(results, 2); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("HideMatcher", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("flow/flow-hide-matcher.yaml", "scanme.sh", suite.debug)
		if err != nil {
			t.Fatalf("hide matcher flow request failed: %v", err)
		}
		if err := expectResultsCount(results, 0); err != nil {
			t.Fatal(err)
		}
	})
}

func getBase64(input string) string {
	return base64.StdEncoding.EncodeToString([]byte(input))
}
