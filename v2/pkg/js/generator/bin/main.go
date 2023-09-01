package main

import (
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/generator"
)

func main() {
	if err := process(os.Args[1]); err != nil {
		log.Fatal(err)
	}
}

func process(directory string) error {
	modules, err := generator.GetLibraryModules(directory)
	if err != nil {
		return errors.Wrap(err, "could not get library modules")
	}
	for _, module := range modules {
		log.Printf("[module] Generating %s", module)

		data, err := generator.CreateTemplateData(filepath.Join(directory, module), "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/")
		if err != nil {
			return fmt.Errorf("could not create template data: %v", err)
		}

		prefixed := "lib" + module
		err = data.WriteJSTemplate(path.Join(directory, "../generated/js/"+prefixed), module)
		if err != nil {
			return fmt.Errorf("could not write js template: %v", err)
		}
		err = data.WriteGoTemplate(path.Join(directory, "../generated/go/"+prefixed), module)
		if err != nil {
			return fmt.Errorf("could not write go template: %v", err)
		}
		err = data.WriteMarkdownLibraryDocumentation(path.Join(directory, "../generated/markdown/"), module)
		if err != nil {
			return fmt.Errorf("could not write markdown template: %v", err)
		}

		data.InitNativeScripts()
		err = data.WriteMarkdownIndexTemplate(path.Join(directory, "../generated/markdown/"))
		if err != nil {
			return fmt.Errorf("could not write markdown index template: %v", err)
		}
	}
	return nil
}
