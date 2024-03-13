package main

import (
	"flag"
	"fmt"
	"log"
	"path"
	"path/filepath"

	"github.com/pkg/errors"
	generator "github.com/projectdiscovery/nuclei/v3/pkg/js/devtools/bindgen"
	fileutil "github.com/projectdiscovery/utils/file"
)

var (
	dir           string
	generatedDir  string
	targetModules string
)

func main() {
	flag.StringVar(&dir, "dir", "libs", "directory to process")
	flag.StringVar(&generatedDir, "out", "generated", "directory to output generated files")
	flag.StringVar(&targetModules, "target", "", "target modules to generate")
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
		// if no modules are found, then given directory is the module itself
		targetModules = path.Base(dir)
		modules = append(modules, targetModules)
		dir = filepath.Dir(dir)
	}
	for _, module := range modules {
		log.Printf("[module] Generating %s", module)

		data, err := generator.CreateTemplateData(filepath.Join(dir, module), "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/")
		if err != nil {
			return fmt.Errorf("could not create template data: %v", err)
		}

		prefixed := "lib" + module
		// if !goOnly {
		// 	err = data.WriteJSTemplate(filepath.Join(generatedDir, "js/"+prefixed), module)
		// 	if err != nil {
		// 		return fmt.Errorf("could not write js template: %v", err)
		// 	}
		// }
		err = data.WriteGoTemplate(path.Join(generatedDir, "go/"+prefixed), module)
		if err != nil {
			return fmt.Errorf("could not write go template: %v", err)
		}
		// disabled for now since we have static website for docs
		// err = data.WriteMarkdownLibraryDocumentation(path.Join(generatedDir, "markdown/"), module)
		// if err != nil {
		// 	return fmt.Errorf("could not write markdown template: %v", err)
		// }

		// err = data.WriteMarkdownIndexTemplate(path.Join(generatedDir, "markdown/"))
		// if err != nil {
		// 	return fmt.Errorf("could not write markdown index template: %v", err)
		// }
		data.InitNativeScripts()
	}
	return nil
}
