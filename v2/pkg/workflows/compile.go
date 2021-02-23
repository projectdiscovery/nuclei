package workflows

import (
	"os"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"gopkg.in/yaml.v2"
)

// Parse a yaml workflow file
func Parse(file string, options *protocols.ExecuterOptions) (*Workflow, error) {
	workflow := &Workflow{options: options}

	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	err = yaml.NewDecoder(f).Decode(workflow)
	if err != nil {
		return nil, err
	}

	if len(workflow.Workflows) == 0 {
		return nil, errors.New("no workflow defined")
	}
	return workflow, nil
}
