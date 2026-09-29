package generators

import (
	"os"
	"testing"
)

func TestParseEnvVars(t *testing.T) {
	old := os.Environ()
	// set a scoped env var
	_ = os.Setenv("NUCLEI_TEST_K", "V1")
	t.Cleanup(func() {
		// restore
		for _, kv := range old {
			parts := kv
			_ = parts // nothing, environment already has superset; best-effort cleanup below
		}
		_ = os.Unsetenv("NUCLEI_TEST_K")
	})
	vars := parseEnvVars()
	if vars["NUCLEI_TEST_K"] != "V1" {
		t.Fatalf("expected V1, got %v", vars["NUCLEI_TEST_K"])
	}
}

func TestEnvVarsMemoization(t *testing.T) {
	// reset memoized map
	envVars = nil
	_ = os.Setenv("NUCLEI_TEST_MEMO", "A")
	t.Cleanup(func() { _ = os.Unsetenv("NUCLEI_TEST_MEMO") })
	v1 := EnvVars()["NUCLEI_TEST_MEMO"]
	// change env after memoization
	_ = os.Setenv("NUCLEI_TEST_MEMO", "B")
	v2 := EnvVars()["NUCLEI_TEST_MEMO"]
	if v1 != "A" || v2 != "A" {
		t.Fatalf("memoization failed: %v %v", v1, v2)
	}
}
