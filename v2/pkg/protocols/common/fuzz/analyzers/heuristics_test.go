package analyzers

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/fuzz/component"
	"github.com/projectdiscovery/retryablehttp-go"
)

func TestHeuristicsAnalyzer(t *testing.T) {
	analyzer := &HeuristicsAnalyzer{}

	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)

	req, err := retryablehttp.NewRequest("GET", "http://testphp.vulnweb.com/artists.php?artist=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	queryComponent := component.NewQuery()
	parsed, err := queryComponent.Parse(req)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed {
		t.Fatal("could not parse request")
	}

	analysis, err := analyzer.Analyze(client, &AnalyzerInput{
		Key:           "artist",
		Value:         "1 AND 433=433",
		OriginalValue: "1",
		Request:       req,
		Component:     queryComponent,
		FinalArgs: map[string]interface{}{
			"true":  "1 AND 433=433",
			"false": "1 AND 6432=1234",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = analysis
}
