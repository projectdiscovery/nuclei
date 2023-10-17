package variables

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestVariablesEvaluate(t *testing.T) {
	data := `a2: "{{md5('test')}}"
a3: "this_is_random_text"
a4: "{{date_time('%Y-%M-%D')}}"
a5: "{{reverse(hostname)}}"
a6: "123456"`

	variables := Variable{}
	err := yaml.Unmarshal([]byte(data), &variables)
	require.NoError(t, err, "could not unmarshal variables")

	result := variables.Evaluate(map[string]interface{}{"hostname": "google.com"})
	a4 := time.Now().Format("2006-01-02")
	require.Equal(t, map[string]interface{}{"a2": "098f6bcd4621d373cade4e832627b4f6", "a3": "this_is_random_text", "a4": a4, "a5": "moc.elgoog", "a6": "123456"}, result, "could not get correct elements")

	// json
	data = `{
  "a2": "{{md5('test')}}",
  "a3": "this_is_random_text",
  "a4": "{{date_time('%Y-%M-%D')}}",
  "a5": "{{reverse(hostname)}}",
  "a6": "123456"
}`
	variables = Variable{}
	err = json.Unmarshal([]byte(data), &variables)
	require.NoError(t, err, "could not unmarshal json variables")

	result = variables.Evaluate(map[string]interface{}{"hostname": "google.com"})
	a4 = time.Now().Format("2006-01-02")
	require.Equal(t, map[string]interface{}{"a2": "098f6bcd4621d373cade4e832627b4f6", "a3": "this_is_random_text", "a4": a4, "a5": "moc.elgoog", "a6": "123456"}, result, "could not get correct elements")

}
