package main

import (
	"flag"
	"fmt"
	"log"
	"path"
	"path/filepath"

	"github.com/pkg/errors"
	generator "github.com/projectdiscovery/nuclei/v2/pkg/js/devtools/bindgen"
	fileutil "github.com/projectdiscovery/utils/file"
)

var (
	dir          string
	generatedDir string
)

func main() {
	flag.StringVar(&dir, "dir", "libs", "directory to process")
	flag.StringVar(&generatedDir, "out", "generated", "directory to output generated files")
	flag.Parse()
	log.SetFlags(0)
	if !fileutil.FolderExists(dir) {
		log.Fatalf("directory %s does not exist", dir)
	}
	if err := process(); err != nil {
		log.Fatal(err)
	}
}

func process() error {
	modules, err := generator.GetLibraryModules(dir)
	if err != nil {
		return errors.Wrap(err, "could not get library modules")
	}
	if len(modules) == 0 && fileutil.FolderExists(dir) {
		// given directory is itself a module
		modules = append(modules, dir)
	}
	for _, module := range modules {
		log.Printf("[module] Generating %s", module)

		data, err := generator.CreateTemplateData(filepath.Join(dir, module), "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/")
		if err != nil {
			return fmt.Errorf("could not create template data: %v", err)
		}

		prefixed := "lib" + module
		err = data.WriteJSTemplate(filepath.Join(generatedDir, "js/"+prefixed), module)
		if err != nil {
			return fmt.Errorf("could not write js template: %v", err)
		}
		err = data.WriteGoTemplate(path.Join(generatedDir, "go/"+prefixed), module)
		if err != nil {
			return fmt.Errorf("could not write go template: %v", err)
		}
		err = data.WriteMarkdownLibraryDocumentation(path.Join(generatedDir, "markdown/"), module)
		if err != nil {
			return fmt.Errorf("could not write markdown template: %v", err)
		}

		data.InitNativeScripts()
		err = data.WriteMarkdownIndexTemplate(path.Join(generatedDir, "markdown/"))
		if err != nil {
			return fmt.Errorf("could not write markdown index template: %v", err)
		}
	}
	return nil
}
