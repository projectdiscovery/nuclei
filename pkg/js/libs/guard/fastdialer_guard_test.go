package jslibs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJSLibsDoNotDialFastdialerDirectly(t *testing.T) {
	root := ".."
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(path, string(filepath.Join("guard"))) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)
		if strings.Contains(content, "Fastdialer.Dial") || strings.Contains(content, "Fastdialer.DialTLS") {
			offenders = append(offenders, path)
		}
		return nil
	})
	requireNoError(t, err)
	if len(offenders) > 0 {
		t.Fatalf("js libs must dial via protocolstate.DialAllowed, offenders: %v", offenders)
	}
}
