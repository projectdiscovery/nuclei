package types

import (
	"testing"
)

// TestOptionsCopyHoneypotFields verifies that Options.Copy() propagates honeypot fields.
func TestOptionsCopyHoneypotFields(t *testing.T) {
	original := &Options{
		HoneypotThreshold:       50,
		HoneypotSuppressResults: true,
	}

	copied := original.Copy()

	if copied.HoneypotThreshold != original.HoneypotThreshold {
		t.Errorf("Copy() did not preserve HoneypotThreshold: got %d, want %d", copied.HoneypotThreshold, original.HoneypotThreshold)
	}
	if copied.HoneypotSuppressResults != original.HoneypotSuppressResults {
		t.Errorf("Copy() did not preserve HoneypotSuppressResults: got %v, want %v", copied.HoneypotSuppressResults, original.HoneypotSuppressResults)
	}
}
