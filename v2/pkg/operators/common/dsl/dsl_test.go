package dsl

import (
	"compress/gzip"
	"fmt"
	"io/ioutil"
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

func Test(t *testing.T) {
	expectedColorizedSignatures := []string{
		"\x1b[93mbase64_py\x1b[0m(arg1 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mprint_debug\x1b[0m(args \x1b[38;5;208m...interface{}\x1b[0m)\x1b[38;5;208m\x1b[0m",
		"\x1b[93mregex\x1b[0m(arg1, arg2 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mmmh3\x1b[0m(arg1 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mto_lower\x1b[0m(arg1 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mmd5\x1b[0m(arg1 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mreplace_regex\x1b[0m(arg1, arg2, arg3 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mhtml_unescape\x1b[0m(arg1 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mhex_encode\x1b[0m(arg1 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mrand_base\x1b[0m(length \x1b[38;5;208muint\x1b[0m, optionalCharSet \x1b[38;5;208mstring\x1b[0m)\x1b[38;5;208m string\x1b[0m",
		"\x1b[93msha1\x1b[0m(arg1 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mtrim_right\x1b[0m(arg1, arg2 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mwait_for\x1b[0m(seconds \x1b[38;5;208muint\x1b[0m)\x1b[38;5;208m\x1b[0m",
		"\x1b[93mtrim\x1b[0m(arg1, arg2 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93murl_encode\x1b[0m(arg1 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mto_upper\x1b[0m(arg1 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mrand_text_alpha\x1b[0m(length \x1b[38;5;208muint\x1b[0m, optionalBadChars \x1b[38;5;208mstring\x1b[0m)\x1b[38;5;208m string\x1b[0m",
		"\x1b[93msha256\x1b[0m(arg1 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mgzip\x1b[0m(arg1 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mlen\x1b[0m(arg1 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mtrim_space\x1b[0m(arg1 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mrand_int\x1b[0m(optionalMin, optionalMax \x1b[38;5;208muint\x1b[0m)\x1b[38;5;208m int\x1b[0m",
		"\x1b[93mremove_bad_chars\x1b[0m(arg1, arg2 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mrand_char\x1b[0m(optionalCharSet \x1b[38;5;208mstring\x1b[0m)\x1b[38;5;208m string\x1b[0m",
		"\x1b[93mreverse\x1b[0m(arg1 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mhtml_escape\x1b[0m(arg1 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mbase64\x1b[0m(arg1 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mbase64_decode\x1b[0m(arg1 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mhex_decode\x1b[0m(arg1 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mtrim_prefix\x1b[0m(arg1, arg2 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93murl_decode\x1b[0m(arg1 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mreplace\x1b[0m(arg1, arg2, arg3 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mtrim_suffix\x1b[0m(arg1, arg2 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mrand_text_numeric\x1b[0m(length \x1b[38;5;208muint\x1b[0m, optionalBadNumbers \x1b[38;5;208mstring\x1b[0m)\x1b[38;5;208m string\x1b[0m",
		"\x1b[93mcontains\x1b[0m(arg1, arg2 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mgenerate_java_gadget\x1b[0m(arg1, arg2, arg3 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93munix_time\x1b[0m(optionalSeconds \x1b[38;5;208muint\x1b[0m)\x1b[38;5;208m float64\x1b[0m",
		"\x1b[93mtrim_left\x1b[0m(arg1, arg2 \x1b[38;5;208minterface{}\x1b[0m)\x1b[38;5;208m interface{}\x1b[0m",
		"\x1b[93mrand_text_alphanumeric\x1b[0m(length \x1b[38;5;208muint\x1b[0m, optionalBadChars \x1b[38;5;208mstring\x1b[0m)\x1b[38;5;208m string\x1b[0m",
	}
	assert.ElementsMatch(t, expectedColorizedSignatures, colorizeDslFunctionSignatures())
}
