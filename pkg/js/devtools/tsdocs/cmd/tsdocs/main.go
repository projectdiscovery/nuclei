package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/projectdiscovery/nuclei/v3/pkg/js/devtools/tsdocs"
	fileutil "github.com/projectdiscovery/utils/file"
)

// Define your template
//
//go:embed tsmodule.go.tmpl
var tsTemplate string

func main() {
	// Create an instance of the template
	tmpl := template.New("ts")
	tmpl = tmpl.Funcs(template.FuncMap{
		"splitLines": func(s string) []string {
			tmp := strings.Split(s, "\n")
			filtered := []string{}
			for _, line := range tmp {
				if strings.TrimSpace(line) != "" {
					filtered = append(filtered, line)
				}
			}
			return filtered
		},
	})
	var err error
	tmpl, err = tmpl.Parse(tsTemplate)
	if err != nil {
		panic(err)
	}
	_ = tmpl

	_ = fileutil.CreateFolder("src")

	filepath.WalkDir("../../../../libs", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			ep, err := tsdocs.NewEntityParser(path)
			if err != nil {
				panic(err)
			}
			if err := ep.Parse(); err != nil {
				panic(err)
			}
			var buff bytes.Buffer
			err = tmpl.Execute(&buff, ep.GetEntities())
			if err != nil {
				panic(err)
			}
			fmt.Printf("Done with %s\n", path)
			_ = os.WriteFile(fmt.Sprintf("src/%s.ts", strings.TrimSuffix(filepath.Base(path), ".go")), buff.Bytes(), 0755)
		}
		return nil
	})

}
