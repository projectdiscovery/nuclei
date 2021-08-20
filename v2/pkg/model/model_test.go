package model

import (
	"encoding/json"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/internal/severity"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

func TestInfoJsonMarshal(t *testing.T) {
	info := Info{
		Name:           "Test Template Name",
		Authors:        StringSlice{[]string{"forgedhallpass", "ice3man"}},
		Description:    "Test description",
		SeverityHolder: severity.SeverityHolder{Severity: severity.High},
		Tags:           StringSlice{[]string{"cve", "misc"}},
		Reference:      StringSlice{"reference1"},
	}

	result, err := json.Marshal(&info)
	assert.Nil(t, err)

	expected := `{"name":"Test Template Name","author":["forgedhallpass","ice3man"],"tags":["cve","misc"],"description":"Test description","reference":"reference1","severity":"high"}`
	assert.Equal(t, expected, string(result))
}

func TestInfoYamlMarshal(t *testing.T) {
	info := Info{
		Name:           "Test Template Name",
		Authors:        StringSlice{[]string{"forgedhallpass", "ice3man"}},
		Description:    "Test description",
		SeverityHolder: severity.SeverityHolder{Severity: severity.High},
		Tags:           StringSlice{[]string{"cve", "misc"}},
		Reference:      StringSlice{"reference1"},
	}

	result, err := yaml.Marshal(&info)
	assert.Nil(t, err)

	expected := `name: Test Template Name
author:
- forgedhallpass
- ice3man
tags:
- cve
- misc
description: Test description
reference: reference1
severity: high
`
	assert.Equal(t, expected, string(result))
}
