package planner

import (
	"fmt"
	"log"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalogue"
)

func TestPlanning(t *testing.T) {
	catalogue, err := catalogue.New("projectdiscovery/nuclei-templates", []string{
		"tokens/",
		"dns/",
		"panels/",
		"subdomain-takeover/",
		"vulnerabilities/",
		"cves/",
		"files/",
		"technologies/",
		"workflows/",
		"default-credentials/",
		"generic-detections/",
		"security-misconfiguration/",
	}, nil)
	if err != nil {
		log.Fatalf("%s\n", err)
	}

	plan, err := Plan(catalogue.GetCompiledInput())
	if err != nil {
		log.Fatalf("%s\n", err)
	}

	for i, step := range plan.steps {
		fmt.Printf("[%d] %v\n", i+1, step)
	}
}
