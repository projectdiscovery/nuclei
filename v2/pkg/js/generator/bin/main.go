package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/projectdiscovery/nuclei/v2/pkg/js/generator"
)

// 1. Requires js-beautify node plugin installed in $PATH.
// 2. Requires gofmt installed in $PATH.

func main() {
	if err := process(os.Args[1]); err != nil {
		log.Fatal(err)
	}
}

func process(directory string) error {
	modules, err := generator.GetModules(directory)
	if err != nil {
		return fmt.Errorf("could not get modules: %v", err)
	}
	for _, module := range modules {
		log.Printf("[module] Generating %s", module)
		data, err := generator.CreateTemplateData(filepath.Join(directory, module), "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/")
		if err != nil {
			return fmt.Errorf("could not create template data: %v", err)
		}
		marshalled, _ := json.MarshalIndent(data, "", "  ")
		fmt.Printf("%+v\n", string(marshalled))

		prefixed := "lib" + module
		err = data.WriteJSTemplate(path.Join(directory, "../generated/js/"+prefixed), module)
		if err != nil {
			return fmt.Errorf("could not write js template: %v", err)
		}
		err = data.WriteGoTemplate(path.Join(directory, "../generated/go/"+prefixed), module)
		if err != nil {
			return fmt.Errorf("could not write go template: %v", err)
		}
		err = data.WriteMarkdownTemplate(path.Join(directory, "../generated/markdown/"), module)
		if err != nil {
			return fmt.Errorf("could not write markdown template: %v", err)
		}
		data.InitNativeScripts()

		err = data.WriteMarkdownIndexTemplate(path.Join(directory, "../generated/markdown/"))
		if err != nil {
			return fmt.Errorf("could not write markdown index template: %v", err)
		}
		//	generate(module)
	}

	//	file, err := os.Create("index.json")
	//	if err != nil {
	//		return fmt.Errorf("could not create index file: %v", err)
	//	}
	//	defer file.Close()
	//
	//	encoder := json.NewEncoder(file)
	//	encoder.SetIndent("", "  ")
	//	if err := encoder.Encode(index); err != nil {
	//		return fmt.Errorf("could not encode index: %v", err)
	//	}
	return nil
}
