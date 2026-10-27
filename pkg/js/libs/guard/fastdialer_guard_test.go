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
		if d.IsDir() {
			if path != root && d.Name() == "guard" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
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
