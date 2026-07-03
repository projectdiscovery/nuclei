//go:build integration
// +build integration

package integration_test

import (
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
)

func TestFile(t *testing.T) {
	target := filepath.ToSlash(filepath.Join("protocols", "file", "data")) + "/"

	t.Run("MatcherWithOr", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/file/matcher-with-or.yaml", target, suite.debug, "-file")
		if err != nil {
			t.Fatalf("file OR matcher request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("MatcherWithAnd", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/file/matcher-with-and.yaml", target, suite.debug, "-file")
		if err != nil {
			t.Fatalf("file AND matcher request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("MatcherWithNestedAnd", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/file/matcher-with-nested-and.yaml", target, suite.debug, "-file")
		if err != nil {
			t.Fatalf("file nested AND matcher request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Extract", func(t *testing.T) {
		results, err := testutils.RunNucleiTemplateAndGetResults("protocols/file/extract.yaml", target, suite.debug, "-file")
		if err != nil {
			t.Fatalf("file extractor request failed: %v", err)
		}
		if err := expectResultsCount(results, 1); err != nil {
			t.Fatal(err)
		}
	})
}
