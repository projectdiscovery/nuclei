package responsehighlighter

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
)

const input = "abcdefghijklmnabcdefghijklmnabcdefghijklmnabcdefghijklmnabcdefghijklmnabcdefghijklmnabcdefghijklmnabcdefghijklmnabcdefghijklmn"

func TestHexDumpHighlighting(t *testing.T) {
	const highlightedHexDumpResponse = `00000000  61 62 63 [32m64[0m [32m65[0m [32m66[0m [32m67[0m [32m68[0m  [32m69[0m [32m6a[0m 6b 6c 6d 6e 61 62  |abc[32md[0m[32me[0m[32mf[0m[32mg[0m[32mh[0m[32mi[0m[32mj[0mklmnab|
00000010  63 [32m64[0m [32m65[0m [32m66[0m [32m67[0m [32m68[0m [32m69[0m [32m6a[0m  6b 6c 6d 6e 61 62 63 [32m64[0m  |c[32md[0m[32me[0m[32mf[0m[32mg[0m[32mh[0m[32mi[0m[32mj[0mklmnabc[32md[0m|
00000020  [32m65[0m [32m66[0m [32m67[0m [32m68[0m [32m69[0m [32m6a[0m 6b 6c  6d 6e 61 62 63 [32m64[0m [32m65[0m [32m66[0m  |[32me[0m[32mf[0m[32mg[0m[32mh[0m[32mi[0m[32mj[0mklmnabc[32md[0m[32me[0m[32mf[0m|
00000030  [32m67[0m [32m68[0m [32m69[0m [32m6a[0m 6b 6c 6d 6e  61 62 63 [32m64[0m [32m65[0m [32m66[0m [32m67[0m [32m68[0m  |[32mg[0m[32mh[0m[32mi[0m[32mj[0mklmnabc[32md[0m[32me[0m[32mf[0m[32mg[0m[32mh[0m|
00000040  [32m69[0m [32m6a[0m 6b 6c 6d 6e 61 62  63 [32m64[0m [32m65[0m [32m66[0m [32m67[0m [32m68[0m [32m69[0m [32m6a[0m  |[32mi[0m[32mj[0mklmnabc[32md[0m[32me[0m[32mf[0m[32mg[0m[32mh[0m[32mi[0m[32mj[0m|
00000050  6b 6c 6d 6e 61 62 63 [32m64[0m  [32m65[0m [32m66[0m [32m67[0m [32m68[0m [32m69[0m [32m6a[0m 6b 6c  |klmnabc[32md[0m[32me[0m[32mf[0m[32mg[0m[32mh[0m[32mi[0m[32mj[0mkl|
00000060  6d 6e 61 62 63 [32m64[0m [32m65[0m [32m66[0m  [32m67[0m [32m68[0m [32m69[0m [32m6a[0m 6b 6c 6d 6e  |mnabc[32md[0m[32me[0m[32mf[0m[32mg[0m[32mh[0m[32mi[0m[32mj[0mklmn|
00000070  61 62 63 [32m64[0m [32m65[0m [32m66[0m [32m67[0m [32m68[0m  [32m69[0m [32m6a[0m 6b 6c 6d 6e        |abc[32md[0m[32me[0m[32mf[0m[32mg[0m[32mh[0m[32mi[0m[32mj[0mklmn|
`
	t.Run("Test highlighting when the snippet is wrapped", func(t *testing.T) {
		result, err := toHighLightedHexDump(hex.Dump([]byte(input)), "defghij")
		assert.Nil(t, err)
		assert.Equal(t, highlightedHexDumpResponse, result.String())
	})

	t.Run("Test highlight when the snippet contains separator character", func(t *testing.T) {
		value := "asdfasdfasda|basdfadsdfs|"
		result, err := toHighLightedHexDump(hex.Dump([]byte(value)), "a|b")

		expected := `00000000  61 73 64 66 61 73 64 66  61 73 64 [32m61[0m [32m7c[0m [32m62[0m 61 73  |asdfasdfasd[32ma[0m[32m|[0m[32mb[0mas|
00000010  64 66 61 64 73 64 66 73  7c                       |dfadsdfs||
`
		assert.Nil(t, err)
		assert.Equal(t, expected, result.String())
	})
}

func TestHighlight(t *testing.T) {
	const multiSnippetHighlightHexDumpResponse = `00000000  [32m61[0m [32m62[0m 63 [32m64[0m [32m65[0m [32m66[0m [32m67[0m [32m68[0m  [32m69[0m [32m6a[0m 6b 6c 6d 6e [32m61[0m [32m62[0m  |[32ma[0m[32mb[0mc[32md[0m[32me[0m[32mf[0m[32mg[0m[32mh[0m[32mi[0m[32mj[0mklmn[32ma[0m[32mb[0m|
00000010  63 [32m64[0m [32m65[0m [32m66[0m [32m67[0m [32m68[0m [32m69[0m [32m6a[0m  6b 6c 6d 6e [32m61[0m [32m62[0m 63 [32m64[0m  |c[32md[0m[32me[0m[32mf[0m[32mg[0m[32mh[0m[32mi[0m[32mj[0mklmn[32ma[0m[32mb[0mc[32md[0m|
00000020  [32m65[0m [32m66[0m [32m67[0m [32m68[0m [32m69[0m [32m6a[0m 6b 6c  6d 6e [32m61[0m [32m62[0m 63 [32m64[0m [32m65[0m [32m66[0m  |[32me[0m[32mf[0m[32mg[0m[32mh[0m[32mi[0m[32mj[0mklmn[32ma[0m[32mb[0mc[32md[0m[32me[0m[32mf[0m|
00000030  [32m67[0m [32m68[0m [32m69[0m [32m6a[0m 6b 6c 6d 6e  [32m61[0m [32m62[0m 63 [32m64[0m [32m65[0m [32m66[0m [32m67[0m [32m68[0m  |[32mg[0m[32mh[0m[32mi[0m[32mj[0mklmn[32ma[0m[32mb[0mc[32md[0m[32me[0m[32mf[0m[32mg[0m[32mh[0m|
00000040  [32m69[0m [32m6a[0m 6b 6c 6d 6e [32m61[0m [32m62[0m  63 [32m64[0m [32m65[0m [32m66[0m [32m67[0m [32m68[0m [32m69[0m [32m6a[0m  |[32mi[0m[32mj[0mklmn[32ma[0m[32mb[0mc[32md[0m[32me[0m[32mf[0m[32mg[0m[32mh[0m[32mi[0m[32mj[0m|
00000050  6b 6c 6d 6e [32m61[0m [32m62[0m 63 [32m64[0m  [32m65[0m [32m66[0m [32m67[0m [32m68[0m [32m69[0m [32m6a[0m 6b 6c  |klmn[32ma[0m[32mb[0mc[32md[0m[32me[0m[32mf[0m[32mg[0m[32mh[0m[32mi[0m[32mj[0mkl|
00000060  6d 6e [32m61[0m [32m62[0m 63 [32m64[0m [32m65[0m [32m66[0m  [32m67[0m [32m68[0m [32m69[0m [32m6a[0m 6b 6c 6d 6e  |mn[32ma[0m[32mb[0mc[32md[0m[32me[0m[32mf[0m[32mg[0m[32mh[0m[32mi[0m[32mj[0mklmn|
00000070  [32m61[0m [32m62[0m 63 [32m64[0m [32m65[0m [32m66[0m [32m67[0m [32m68[0m  [32m69[0m [32m6a[0m 6b 6c 6d 6e        |[32ma[0m[32mb[0mc[32md[0m[32me[0m[32mf[0m[32mg[0m[32mh[0m[32mi[0m[32mj[0mklmn|
`
	matches := map[string][]string{
		"first":  {"defghij"},
		"second": {"ab"},
	}
	operatorResult := operators.Result{Matches: matches}

	t.Run("Test highlighting when the snippet is wrapped", func(t *testing.T) {
		result := Highlight(&operatorResult, hex.Dump([]byte(input)), false, true)
		assert.Equal(t, multiSnippetHighlightHexDumpResponse, result)
	})

	t.Run("Test highlighting without hexdump", func(t *testing.T) {
		result := Highlight(&operatorResult, input, false, false)
		expected := `[32mab[0mc[32mdefghij[0mklmn[32mab[0mc[32mdefghij[0mklmn[32mab[0mc[32mdefghij[0mklmn[32mab[0mc[32mdefghij[0mklmn[32mab[0mc[32mdefghij[0mklmn[32mab[0mc[32mdefghij[0mklmn[32mab[0mc[32mdefghij[0mklmn[32mab[0mc[32mdefghij[0mklmn[32mab[0mc[32mdefghij[0mklmn`
		assert.Equal(t, expected, result)
	})

	t.Run("Test the response is not modified if noColor is true", func(t *testing.T) {
		result := Highlight(&operatorResult, input, true, false)
		assert.Equal(t, input, result)
	})

	t.Run("Test the response is not modified if noColor is true", func(t *testing.T) {
		result := Highlight(&operatorResult, hex.Dump([]byte(input)), true, true)
		assert.Equal(t, hex.Dump([]byte(input)), result)
	})
}
