package workflows

import (
	"os"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

// Parse a yaml workflow file
func Parse(file string) (*Workflow, error) {
	workflow := &Workflow{}

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
