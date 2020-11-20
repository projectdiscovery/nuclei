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

	if len(workflow.Workflows) > 0 {
		if err := workflow.generateLogicFromWorkflows(); err != nil {
			return nil, errors.Wrap(err, "could not generate workflow")
		}
	}
	if workflow.Logic == "" {
		return nil, errors.New("no logic provided")
	}
	workflow.path = file
	return workflow, nil
}
