package templates

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestTemplateInteractshEvictionUnmarshal(t *testing.T) {
	t.Parallel()

	const raw = `
id: example-oast
info:
  name: example
  author: pdteam
  severity: info
interactsh-eviction: 300
http:
  - method: GET
    path:
      - "{{BaseURL}}"
`
	var template Template
	require.NoError(t, yaml.Unmarshal([]byte(raw), &template))
	require.Equal(t, 300, template.InteractshEviction)
}
