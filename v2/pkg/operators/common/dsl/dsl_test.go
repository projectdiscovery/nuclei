package dsl

import (
	"compress/gzip"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/nebula"
	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

func TestDSLURLEncodeDecode(t *testing.T) {
	encoded, err := nebula.EvalExp("url_encode('&test\"')", nil)
	require.Nil(t, err, "could not url encode")
	require.Equal(t, "%26test%22", encoded, "could not get url encoded data")

	decoded, err := nebula.EvalExp("url_decode('%26test%22')", nil)
	require.Nil(t, err, "could not url encode")
	require.Equal(t, "&test\"", decoded, "could not get url decoded data")
}

func TestDSLTimeComparison(t *testing.T) {
	compiled, err := govaluate.NewEvaluableExpressionWithFunctions("unixtime() > not_after", HelperFunctions())
	require.Nil(t, err, "could not compare time")

	result, err := compiled.Evaluate(map[string]interface{}{"not_after": float64(time.Now().Unix() - 1000)})
	require.Nil(t, err, "could not evaluate compare time")
	require.Equal(t, true, result, "could not get url encoded data")
}

func TestDSLGzipSerialize(t *testing.T) {
	compiled, err := govaluate.NewEvaluableExpressionWithFunctions("gzip(\"hello world\")", HelperFunctions())
	require.Nil(t, err, "could not compare time")

	result, err := compiled.Evaluate(make(map[string]interface{}))
	require.Nil(t, err, "could not evaluate compare time")

	reader, _ := gzip.NewReader(strings.NewReader(types.ToString(result)))
	data, _ := ioutil.ReadAll(reader)

	require.Equal(t, "hello world", string(data), "could not get gzip encoded data")
}
