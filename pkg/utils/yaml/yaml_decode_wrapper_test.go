package yaml

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnmarshalStrictRejectsUnknownFields(t *testing.T) {
	var value struct {
		Name string `yaml:"name"`
	}

	err := UnmarshalStrict([]byte("name: test\nunknown: value\n"), &value)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown")
}

func TestUnmarshalStrictRejectsDuplicateFields(t *testing.T) {
	var value struct {
		Name string `yaml:"name"`
	}

	err := UnmarshalStrict([]byte("name: first\nname: second\n"), &value)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already")
}

func TestUnmarshalLaxAllowsDuplicateFields(t *testing.T) {
	var value struct {
		Name string `yaml:"name"`
	}

	err := Unmarshal([]byte("name: first\nname: second\n"), &value)
	require.NoError(t, err)
	require.Equal(t, "second", value.Name)
}

func TestDecoderLaxAllowsDuplicateFields(t *testing.T) {
	var value struct {
		Name string `yaml:"name"`
	}

	err := NewDecoder(strings.NewReader("name: first\nname: second\n")).Decode(&value)
	require.NoError(t, err)
	require.Equal(t, "second", value.Name)
}

func TestUnmarshalPreservesYAMLv2NestedInterfaceMapShape(t *testing.T) {
	var value map[string]interface{}

	err := Unmarshal([]byte("payload:\n  low:\n    - one\n"), &value)
	require.NoError(t, err)

	nested, ok := value["payload"].(map[interface{}]interface{})
	require.True(t, ok, "nested interface map should keep yaml.v2 map[interface{}]interface{} shape")
	require.Equal(t, []interface{}{"one"}, nested["low"])
}

func TestMapSlicePreservesOrder(t *testing.T) {
	var value MapSlice

	err := Unmarshal([]byte("first: one\nsecond: two\nthird: three\n"), &value)
	require.NoError(t, err)
	require.Len(t, value, 3)
	require.Equal(t, "first", value[0].Key)
	require.Equal(t, "second", value[1].Key)
	require.Equal(t, "third", value[2].Key)
	require.Equal(t, "one", value[0].Value)
	require.Equal(t, "two", value[1].Value)
	require.Equal(t, "three", value[2].Value)
}
