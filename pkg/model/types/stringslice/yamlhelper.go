package stringslice

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"gopkg.in/yaml.v3"
)

type StringNormalizer interface {
	Normalize(value string) string
}

func UnmarshalYAMLNode(node *yaml.Node, normalizer StringNormalizer) ([]string, error) {
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		node = node.Content[0]
	}

	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag == "!!null" {
			return nil, fmt.Errorf("stringslice: null values not supported")
		}
		var v string
		if err := node.Decode(&v); err != nil {
			return nil, err
		}
		if utils.IsBlank(v) {
			return []string{}, nil
		}
		result := strings.Split(v, ",")
		if normalizer != nil {
			for i, value := range result {
				result[i] = normalizer.Normalize(value)
			}
		}
		return result, nil

	case yaml.SequenceNode:
		out := make([]string, 0, len(node.Content))
		for _, c := range node.Content {
			var v string
			if err := c.Decode(&v); err != nil {
				return nil, err
			}
			if normalizer != nil {
				v = normalizer.Normalize(v)
			}
			out = append(out, v)
		}
		return out, nil

	case yaml.AliasNode:
		return UnmarshalYAMLNode(node.Alias, normalizer)

	case 0:
		return nil, fmt.Errorf("stringslice: null values not supported")

	default:
		return nil, fmt.Errorf("stringslice: expected string or sequence, got %v", node.Kind)
	}
}
