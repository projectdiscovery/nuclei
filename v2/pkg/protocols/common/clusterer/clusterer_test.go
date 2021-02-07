package clusterer

import (
	"fmt"
	"log"
	"testing"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalogue"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestHTTPRequestsCluster(t *testing.T) {
	catalogue := catalogue.New("/Users/ice3man/nuclei-templates")
	templatesList, err := catalogue.GetTemplatePath("/Users/ice3man/nuclei-templates")
	require.Nil(t, err, "could not get templates")

	protocolinit.Init(&types.Options{})
	list := make(map[string]*templates.Template)
	for _, template := range templatesList {
		executerOpts := protocols.ExecuterOptions{
			Output:      &mockOutput{},
			Options:     &types.Options{},
			Progress:    nil,
			Catalogue:   catalogue,
			RateLimiter: nil,
			ProjectFile: nil,
		}
		t, err := templates.Parse(template, executerOpts)
		if err != nil {
			continue
		}
		if _, ok := list[t.ID]; !ok {
			list[t.ID] = t
		} else {
			log.Printf("Duplicate template found: %v\n", t)
		}
	}

	totalClusterCount := 0
	totalRequestsSentNew := 0
	new := Cluster(list)
	for i, cluster := range new {
		if len(cluster) == 1 {
			continue
		}
		fmt.Printf("[%d] cluster created:\n", i)
		for _, request := range cluster {
			totalClusterCount++
			fmt.Printf("\t%v\n", request.ID)
		}
		totalRequestsSentNew++
	}
	fmt.Printf("Reduced %d requests to %d via clustering\n", totalClusterCount, totalRequestsSentNew)
}

type mockOutput struct{}

// Close closes the output writer interface
func (m *mockOutput) Close() {}

// Colorizer returns the colorizer instance for writer
func (m *mockOutput) Colorizer() aurora.Aurora {
	return nil
}

// Write writes the event to file and/or screen.
func (m *mockOutput) Write(*output.ResultEvent) error {
	return nil
}

// Request writes a log the requests trace log
func (m *mockOutput) Request(templateID, url, requestType string, err error) {}
