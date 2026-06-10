//go:build integration
// +build integration

package integration_test

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
)

func TestDNS(t *testing.T) {
	t.Run("A", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/dns/a.yaml", "one.one.one.one", suite.debug)
		if err != nil {
			t.Fatalf("dns A request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("AAAA", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/dns/aaaa.yaml", "one.one.one.one", suite.debug)
		if err != nil {
			t.Fatalf("dns AAAA request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("CNAME", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/dns/cname.yaml", "one.one.one.one", suite.debug)
		if err != nil {
			t.Fatalf("dns CNAME request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("SRV", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/dns/srv.yaml", "one.one.one.one", suite.debug)
		if err != nil {
			t.Fatalf("dns SRV request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("NS", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/dns/ns.yaml", "one.one.one.one", suite.debug)
		if err != nil {
			t.Fatalf("dns NS request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("TXT", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/dns/txt.yaml", "one.one.one.one", suite.debug)
		if err != nil {
			t.Fatalf("dns TXT request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("PTR", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/dns/ptr.yaml", "1.1.1.1", suite.debug)
		if err != nil {
			t.Fatalf("dns PTR request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("CAA", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/dns/caa.yaml", "pki.goog", suite.debug)
		if err != nil {
			t.Fatalf("dns CAA request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("TLSA", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/dns/tlsa.yaml", "scanme.sh", suite.debug)
		if err != nil {
			t.Fatalf("dns TLSA request failed: %v", err)
		}
		if err := expectResultsCount(results, 0); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Variables", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/dns/variables.yaml", "one.one.one.one", suite.debug)
		if err != nil {
			t.Fatalf("dns variables request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Payload", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/dns/payload.yaml", "google.com", suite.debug)
		if err != nil {
			t.Fatalf("dns payload request failed: %v", err)
		}
		if err := expectResultsCount(results, 3); err != nil {
			t.Fatal(err)
		}

		results, err = testutils.RunNucleiTemplateAndGetResults("protocols/dns/payload.yaml", "google.com", suite.debug, "-var", "subdomain_wordlist=subdomains.txt")
		if err != nil {
			t.Fatalf("dns payload request with CLI override failed: %v", err)
		}
		if err := expectResultsCount(results, 4); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("DSLMatcherVariable", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/dns/dsl-matcher-variable.yaml", "one.one.one.one", suite.debug)
		if err != nil {
			t.Fatalf("dns DSL matcher variable request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})
}
