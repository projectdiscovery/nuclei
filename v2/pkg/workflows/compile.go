package workflows

import (
	"errors"
	"os"

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

	if workflow.Logic == "" {
		return nil, errors.New("no logic provided")
	}

	workflow.path = file

	return workflow, nil
}
