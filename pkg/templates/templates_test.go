package templates

import (
	"os"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestCachePoolZeroing(t *testing.T) {
	c := NewCache()

	tpl := &Template{ID: "x"}
	raw := []byte("SOME BIG RAW")

	c.Store("id1", tpl, raw, nil)
	gotTpl, gotErr := c.Get("id1")
	if gotErr != nil {
		t.Fatalf("unexpected err: %v", gotErr)
	}
	if gotTpl == nil || gotTpl.ID != "x" {
		t.Fatalf("unexpected tpl: %#v", gotTpl)
	}

	// StoreWithoutRaw should not retain raw
	c.StoreWithoutRaw("id2", tpl, nil)
	gotTpl2, gotErr2 := c.Get("id2")
	if gotErr2 != nil {
		t.Fatalf("unexpected err: %v", gotErr2)
	}
	if gotTpl2 == nil || gotTpl2.ID != "x" {
		t.Fatalf("unexpected tpl2: %#v", gotTpl2)
	}
}

func TestTemplateStruct(t *testing.T) {
	templatePath := "./tests/match-1.yaml"
	bin, err := os.ReadFile(templatePath)
	require.Nil(t, err, "failed to load example template")
	var yamlTemplate Template
	err = yaml.Unmarshal(bin, &yamlTemplate)
	require.Nil(t, err, "failed to unmarshal yaml template")
	jsonBin, err := json.Marshal(yamlTemplate)
	require.Nil(t, err, "failed to marshal template to json")
	var jsonTemplate Template
	err = json.Unmarshal(jsonBin, &jsonTemplate)
	require.Nil(t, err, "failed to unmarshal json template")

	templatePath = "./tests/json-template.json"
	bin, err = os.ReadFile(templatePath)
	require.Nil(t, err, "failed to load example template")
	jsonTemplate = Template{}
	err = json.Unmarshal(bin, &jsonTemplate)
	require.Nil(t, err, "failed to unmarshal json template")
	yamlBin, err := yaml.Marshal(jsonTemplate)
	require.Nil(t, err, "failed to marshal template to yaml")
	yamlTemplate = Template{}
	err = yaml.Unmarshal(yamlBin, &yamlTemplate)
	require.Nil(t, err, "failed to unmarshal yaml template")
}
