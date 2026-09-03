// Command techgraph-gen builds the offline tech-graph.json artifact from a local
// nuclei-templates checkout. See pkg/protocols/common/automaticscan/AUTOMATIC_SCAN_V2.md.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/automaticscan/techgraph"
)

func main() {
	var (
		templates = flag.String("templates", "", "path to nuclei-templates directory (required)")
		output    = flag.String("output", "tech-graph.json", "output artifact path")
		htmlOut   = flag.String("html", "", "also write a standalone visualizer HTML with data inlined")
	)
	flag.Parse()

	if *templates == "" {
		fmt.Fprintln(os.Stderr, "error: -templates is required")
		flag.Usage()
		os.Exit(2)
	}

	graph, err := techgraph.Build(*templates)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: build failed: %v\n", err)
		os.Exit(1)
	}
	if err := graph.WriteFile(*output); err != nil {
		fmt.Fprintf(os.Stderr, "error: write failed: %v\n", err)
		os.Exit(1)
	}
	if *htmlOut != "" {
		html, err := techgraph.StandaloneHTML(graph)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: html render failed: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*htmlOut, []byte(html), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error: html write failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("standalone visualizer written to %s\n", *htmlOut)
	}

	s := graph.Stats
	fmt.Printf("tech-graph written to %s\n", *output)
	fmt.Printf("  templates:  %d (parse-skipped %d)\n", s.Total, s.ParseError)
	fmt.Printf("  dependents: %d (cpe %d, platform %d, dir %d, tag %d, id %d) across %d techs\n",
		s.Dependents, s.DependentsCPE, s.DependentsPlat, s.DependentsDir, s.DependentsTag, s.DependentsID, s.Techs)
	fmt.Printf("  baseline:   %d\n", s.Baseline)
	fmt.Printf("  detection:  %d\n", s.Detection)
	fmt.Printf("  excluded:   %d\n", s.Excluded)
	fmt.Printf("  unmapped:   %d\n", s.Unmapped)
	fmt.Printf("  source:     %s\n", graph.SourceHash)
}
