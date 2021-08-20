package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
)

func main() {
	data, err := templates.GetTemplateDoc().Encode()
	if err != nil {
		log.Fatalf("Could not encode docs: %s\n", err)
	}
	err = ioutil.WriteFile(os.Args[1], data, 0777)
	if err != nil {
		log.Fatalf("Could not write docs: %s\n", err)
	}
}
