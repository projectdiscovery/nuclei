package model

import (
	"encoding/json"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/internal/severity"
	"github.com/stretchr/testify/assert"
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

	expected := `{"name":"Test Template Name","authors":["forgedhallpass","ice3man"],"tags":["cve","misc"],"description":"Test description","reference":"reference1","severity":"high"}`
	assert.Equal(t, expected, string(result))
}
