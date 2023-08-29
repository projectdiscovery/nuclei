package main

import nuclei "github.com/projectdiscovery/nuclei/v2/lib"

func main() {
	ne, err := nuclei.NewNucleiEngine(
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{ProtocolTypes: "dns"}), // only use dns templates
		nuclei.WithConcurrency(nuclei.Concurrency{TemplateConcurrency: 1}),       // never use templateconcurrency 1. this is just for testing
	)
	if err != nil {
		panic(err)
	}
	// load targets and optionally probe non http/https targets
	ne.LoadTargets([]string{"scanme.sh"}, false)
	err = ne.ExecuteWithCallback(nil)
	if err != nil {
		panic(err)
	}
	defer ne.Close()
}
