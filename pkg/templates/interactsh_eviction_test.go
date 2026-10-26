package templates

import (
	"strconv"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
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

	parsed, err := parseTemplateNoVerify([]byte(raw), &protocols.ExecutorOptions{Options: types.DefaultOptions()})
	require.NoError(t, err)
	require.Equal(t, 300, parsed.Options.InteractshEviction)
	require.Equal(t, 300*time.Second, parsed.Options.InteractshEvictionDuration())
}

func TestTemplateInteractshEvictionRejectsNegativeValue(t *testing.T) {
	t.Parallel()

	_, err := prepareTemplate(&Template{InteractshEviction: -1}, nil)
	require.EqualError(t, err, "interactsh-eviction cannot be negative")
}

func TestTemplateInteractshEvictionRejectsOverflow(t *testing.T) {
	t.Parallel()

	if strconv.IntSize < 64 {
		t.Skip("int cannot hold a value above the limit")
	}
	_, err := prepareTemplate(&Template{InteractshEviction: int(interactsh.MaxEvictionSeconds) + 1}, nil)
	require.ErrorContains(t, err, "interactsh-eviction cannot be greater than")
}
