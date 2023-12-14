package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	// _ = tmpl

	// ep, err := tsdocs.NewEntityParser("../../../../libs/structs/structs.go")
	// if err != nil {
	// 	panic(err)
	// }
	// if err := ep.Parse(); err != nil {
	// 	panic(err)
	// }
	// // var buff bytes.Buffer
	// err = tmpl.Execute(os.Stdout, ep.GetEntities())
	// if err != nil {
	// 	panic(err)
	// }

	_ = fileutil.CreateFolder("src")

	dirs := []string{}

	filepath.WalkDir("../../../../libs", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && !strings.HasSuffix(path, "libs") {
			dirs = append(dirs, path)
		}
		return nil
	})

	// walk each directory
	for _, dir := range dirs {
		entityList := []tsdocs.Entity{}
		filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			ep, err := tsdocs.NewEntityParser(path)
			if err != nil {
				panic(err)
			}
			if err := ep.Parse(); err != nil {
				panic(err)
			}
			entityList = append(entityList, ep.GetEntities()...)
			return nil
		})
		entityList = sortEntities(entityList)
		var buff bytes.Buffer
		err = tmpl.Execute(&buff, entityList)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Done with %s\n", dir)
		_ = os.WriteFile(fmt.Sprintf("src/%s.ts", filepath.Base(dir)), buff.Bytes(), 0755)
	}

	// generating index.ts file
	var buff bytes.Buffer
	for _, dir := range dirs {
		buff.WriteString(fmt.Sprintf("export * as %s from './%s';\n", filepath.Base(dir), filepath.Base(dir)))
	}
	_ = os.WriteFile("src/index.ts", buff.Bytes(), 0755)
}

func sortEntities(entities []tsdocs.Entity) []tsdocs.Entity {
	sort.Slice(entities, func(i, j int) bool {
		if entities[i].Type != entities[j].Type {
			// Define the order of types
			order := map[string]int{"function": 1, "class": 2, "interface": 3}
			return order[entities[i].Type] < order[entities[j].Type]
		}
		// If types are the same, sort by name
		return entities[i].Name < entities[j].Name
	})
	return entities
}
