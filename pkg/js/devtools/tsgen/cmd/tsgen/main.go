package main

import (
	"bytes"
	_ "embed"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/devtools/tsgen"
	fileutil "github.com/projectdiscovery/utils/file"
)

// Define your template
//
//go:embed tsmodule.go.tmpl
var tsTemplate string

var (
	source string
	out    string
)

func main() {
	flag.StringVar(&source, "dir", "", "Directory to parse")
	flag.StringVar(&out, "out", "src", "Typescript files Output directory")
	flag.Parse()

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

	// Create the output directory
	_ = fileutil.CreateFolder(out)

	dirs := []string{}
	_ = filepath.WalkDir(source, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// only load module directory skip root directory
		if d.IsDir() {
			files, _ := os.ReadDir(path)
			for _, file := range files {
				if !file.IsDir() && strings.HasSuffix(file.Name(), ".go") {
					dirs = append(dirs, path)
					break
				}
			}
		}
		return nil
	})

	// walk each directory
	for _, dir := range dirs {
		entityList := []tsgen.Entity{}
		ep, err := tsgen.NewEntityParser(dir)
		if err != nil {
			panic(fmt.Errorf("could not create entity parser: %s", err))
		}
		if err := ep.Parse(); err != nil {
			panic(fmt.Errorf("could not parse entities: %s", err))
		}
		entityList = append(entityList, ep.GetEntities()...)
		entityList = sortEntities(entityList)
		var buff bytes.Buffer
		err = tmpl.Execute(&buff, entityList)
		if err != nil {
			panic(err)
		}
		moduleName := filepath.Base(dir)
		gologger.Info().Msgf("Writing %s.ts", moduleName)
		// create appropriate directory if missing
		// _ = fileutil.CreateFolder(filepath.Join(out, moduleName))
		_ = os.WriteFile(filepath.Join(out, moduleName)+".ts", buff.Bytes(), 0755)
	}

	// generating index.ts file
	var buff bytes.Buffer
	for _, dir := range dirs {
		buff.WriteString(fmt.Sprintf("export * as %s from './%s';\n", filepath.Base(dir), filepath.Base(dir)))
	}
	_ = os.WriteFile(filepath.Join(out, "index.ts"), buff.Bytes(), 0755)
}

func sortEntities(entities []tsgen.Entity) []tsgen.Entity {
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
