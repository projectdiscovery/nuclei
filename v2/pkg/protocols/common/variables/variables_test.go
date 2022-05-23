package variables

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestVariablesEvaluate(t *testing.T) {
	data := `a1: "{{rand_base(5)}}"
a2: "{{md5(a1)}}"
a3: "this_is_random_text"
a4: "{{date('%Y-%M-%D')}}"
a5: "{{reverse(hostname)}}"
a6: "123456"`

	variables := Variable{}
	err := yaml.Unmarshal([]byte(data), &variables)
	require.NoError(t, err, "could not unmarshal variables")

	result := variables.Evaluate(map[string]interface{}{"hostname": "google.com"})
	a4 := time.Now().Format("2006-01-02")
	require.Equal(t, map[string]interface{}{"a1": "BpLnf", "a2": "531403a4c6a4133e42d0499b5a6ee60f", "a3": "this_is_random_text", "a4": a4, "a5": "moc.elgoog", "a6": "123456"}, result, "could not get correct elements")
}
