package types

import (
	"testing"

	"github.com/projectdiscovery/goflags"
)

func TestShouldPrefetchSecrets(t *testing.T) {
	t.Run("false by default", func(t *testing.T) {
		opts := &Options{}
		if opts.ShouldPrefetchSecrets() {
			t.Fatalf("expected ShouldPrefetchSecrets to be false")
		}
	})

	t.Run("true when explicit prefetch flag set", func(t *testing.T) {
		opts := &Options{PreFetchSecrets: true}
		if !opts.ShouldPrefetchSecrets() {
			t.Fatalf("expected ShouldPrefetchSecrets to be true when PreFetchSecrets is set")
		}
	})

	t.Run("true when secret-file is set", func(t *testing.T) {
		opts := &Options{SecretsFile: goflags.StringSlice{"secrets.yaml"}}
		if !opts.ShouldPrefetchSecrets() {
			t.Fatalf("expected ShouldPrefetchSecrets to be true when SecretsFile is provided")
		}
	})
}
