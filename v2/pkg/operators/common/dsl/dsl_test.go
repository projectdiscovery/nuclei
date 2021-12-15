package dsl

import (
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Knetic/govaluate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

func TestDSLURLEncodeDecode(t *testing.T) {
	functions := HelperFunctions()

	encoded, err := functions["url_encode"]("&test\"")
	require.Nil(t, err, "could not url encode")
	require.Equal(t, "%26test%22", encoded, "could not get url encoded data")

	decoded, err := functions["url_decode"]("%26test%22")
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

func Test1(t *testing.T) {
	type testCase struct {
		methodName string
		arguments  []interface{}
		expected   interface{}
		err        string
	}

	toUpperSignatureError := createSignatureError("to_upper(arg1 interface{}) interface{}")
	removeBadCharsSignatureError := createSignatureError("remove_bad_chars(arg1, arg2 interface{}) interface{}")

	testCases := []testCase{
		{"to_upper", []interface{}{}, nil, toUpperSignatureError},
		{"to_upper", []interface{}{"a"}, "A", ""},
		{"toupper", []interface{}{"a"}, "A", ""},
		{"to_upper", []interface{}{"a", "b", "c"}, nil, toUpperSignatureError},

		{"remove_bad_chars", []interface{}{}, nil, removeBadCharsSignatureError},
		{"remove_bad_chars", []interface{}{"a"}, nil, removeBadCharsSignatureError},
		{"remove_bad_chars", []interface{}{"abba baab", "b"}, "aa aa", ""},
		{"remove_bad_chars", []interface{}{"a", "b", "c"}, nil, removeBadCharsSignatureError},
	}

	helperFunctions := HelperFunctions()
	for _, currentTestCase := range testCases {
		methodName := currentTestCase.methodName
		t.Run(methodName, func(t *testing.T) {
			actualResult, err := helperFunctions[methodName](currentTestCase.arguments...)

			if currentTestCase.err == "" {
				assert.Nil(t, err)
			} else {
				assert.Equal(t, err.Error(), currentTestCase.err)
			}
			assert.Equal(t, currentTestCase.expected, actualResult)
		})
	}
}

func createSignatureError(signature string) string {
	return fmt.Errorf(invalidDslFunctionMessageTemplate, invalidDslFunctionError, signature).Error()
}

func TestGetPrintableDslFunctionSignatures(t *testing.T) {
	expected := `	[93mbase64[0m(arg1 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mbase64_decode[0m(arg1 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mbase64_py[0m(arg1 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mcontains[0m(arg1, arg2 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mgenerate_java_gadget[0m(arg1, arg2, arg3 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mgzip[0m(arg1 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mhex_decode[0m(arg1 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mhex_encode[0m(arg1 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mhtml_escape[0m(arg1 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mhtml_unescape[0m(arg1 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mlen[0m(arg1 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mmd5[0m(arg1 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mmmh3[0m(arg1 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mprint_debug[0m(args [38;5;208m...interface{}[0m)[38;5;208m[0m
	[93mrand_base[0m(length [38;5;208muint[0m, optionalCharSet [38;5;208mstring[0m)[38;5;208m string[0m
	[93mrand_char[0m(optionalCharSet [38;5;208mstring[0m)[38;5;208m string[0m
	[93mrand_int[0m(optionalMin, optionalMax [38;5;208muint[0m)[38;5;208m int[0m
	[93mrand_text_alpha[0m(length [38;5;208muint[0m, optionalBadChars [38;5;208mstring[0m)[38;5;208m string[0m
	[93mrand_text_alphanumeric[0m(length [38;5;208muint[0m, optionalBadChars [38;5;208mstring[0m)[38;5;208m string[0m
	[93mrand_text_numeric[0m(length [38;5;208muint[0m, optionalBadNumbers [38;5;208mstring[0m)[38;5;208m string[0m
	[93mregex[0m(arg1, arg2 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mremove_bad_chars[0m(arg1, arg2 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mreplace[0m(arg1, arg2, arg3 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mreplace_regex[0m(arg1, arg2, arg3 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mreverse[0m(arg1 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93msha1[0m(arg1 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93msha256[0m(arg1 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mto_lower[0m(arg1 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mto_upper[0m(arg1 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mtrim[0m(arg1, arg2 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mtrim_left[0m(arg1, arg2 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mtrim_prefix[0m(arg1, arg2 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mtrim_right[0m(arg1, arg2 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mtrim_space[0m(arg1 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mtrim_suffix[0m(arg1, arg2 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93munix_time[0m(optionalSeconds [38;5;208muint[0m)[38;5;208m float64[0m
	[93murl_decode[0m(arg1 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93murl_encode[0m(arg1 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m
	[93mwait_for[0m(seconds [38;5;208muint[0m)[38;5;208m[0m
`
	t.Run("with coloring", func(t *testing.T) {
		assert.Equal(t, expected, GetPrintableDslFunctionSignatures(false))
	})

	t.Run("without coloring", func(t *testing.T) {
		var decolorizerRegex = regexp.MustCompile(`\x1B\[[0-9;]*[a-zA-Z]`)
		expectedSignaturesWithoutColor := decolorizerRegex.ReplaceAllString(expected, "")

		assert.Equal(t, expectedSignaturesWithoutColor, GetPrintableDslFunctionSignatures(true))
	})
}
