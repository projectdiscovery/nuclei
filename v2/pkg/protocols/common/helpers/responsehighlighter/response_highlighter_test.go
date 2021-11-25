package responsehighlighter

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
)

const input = "abcdefghijklmnabcdefghijklmnabcdefghijklmnabcdefghijklmnabcdefghijklmnabcdefghijklmnabcdefghijklmnabcdefghijklmnabcdefghijklmn"

func TestHexDumpHighlighting(t *testing.T) {
	highlightedHexDumpResponse :=
		"00000000  61 62 63 \x1b[32m64\x1b[0m \x1b[32m65\x1b[0m \x1b[32m66\x1b[0m \x1b[32m67\x1b[0m \x1b[32m68\x1b[0m  \x1b[32m69\x1b[0m \x1b[32m6a\x1b[0m 6b 6c 6d 6e 61 62  |abc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmnab|\n" +
			"00000010  63 \x1b[32m64\x1b[0m \x1b[32m65\x1b[0m \x1b[32m66\x1b[0m \x1b[32m67\x1b[0m \x1b[32m68\x1b[0m \x1b[32m69\x1b[0m \x1b[32m6a\x1b[0m  6b 6c 6d 6e 61 62 63 \x1b[32m64\x1b[0m  |c\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmnabc\x1b[32md\x1b[0m|\n" +
			"00000020  \x1b[32m65\x1b[0m \x1b[32m66\x1b[0m \x1b[32m67\x1b[0m \x1b[32m68\x1b[0m \x1b[32m69\x1b[0m \x1b[32m6a\x1b[0m 6b 6c  6d 6e 61 62 63 \x1b[32m64\x1b[0m \x1b[32m65\x1b[0m \x1b[32m66\x1b[0m  |\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmnabc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m|\n" +
			"00000030  \x1b[32m67\x1b[0m \x1b[32m68\x1b[0m \x1b[32m69\x1b[0m \x1b[32m6a\x1b[0m 6b 6c 6d 6e  61 62 63 \x1b[32m64\x1b[0m \x1b[32m65\x1b[0m \x1b[32m66\x1b[0m \x1b[32m67\x1b[0m \x1b[32m68\x1b[0m  |\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmnabc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m|\n" +
			"00000040  \x1b[32m69\x1b[0m \x1b[32m6a\x1b[0m 6b 6c 6d 6e 61 62  63 \x1b[32m64\x1b[0m \x1b[32m65\x1b[0m \x1b[32m66\x1b[0m \x1b[32m67\x1b[0m \x1b[32m68\x1b[0m \x1b[32m69\x1b[0m \x1b[32m6a\x1b[0m  |\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmnabc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0m|\n" +
			"00000050  6b 6c 6d 6e 61 62 63 \x1b[32m64\x1b[0m  \x1b[32m65\x1b[0m \x1b[32m66\x1b[0m \x1b[32m67\x1b[0m \x1b[32m68\x1b[0m \x1b[32m69\x1b[0m \x1b[32m6a\x1b[0m 6b 6c  |klmnabc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mkl|\n" +
			"00000060  6d 6e 61 62 63 \x1b[32m64\x1b[0m \x1b[32m65\x1b[0m \x1b[32m66\x1b[0m  \x1b[32m67\x1b[0m \x1b[32m68\x1b[0m \x1b[32m69\x1b[0m \x1b[32m6a\x1b[0m 6b 6c 6d 6e  |mnabc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmn|\n" +
			"00000070  61 62 63 \x1b[32m64\x1b[0m \x1b[32m65\x1b[0m \x1b[32m66\x1b[0m \x1b[32m67\x1b[0m \x1b[32m68\x1b[0m  \x1b[32m69\x1b[0m \x1b[32m6a\x1b[0m 6b 6c 6d 6e        |abc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmn|\n"

	t.Run("Test highlighting when the snippet is wrapped", func(t *testing.T) {
		result, err := toHighLightedHexDump(hex.Dump([]byte(input)), "defghij")
		assert.Nil(t, err)
		assert.Equal(t, highlightedHexDumpResponse, result.String())
	})

	t.Run("Test highlight when the snippet contains separator character", func(t *testing.T) {
		value := "asdfasdfasda|basdfadsdfs|"
		result, err := toHighLightedHexDump(hex.Dump([]byte(value)), "a|b")

		expected :=
			"00000000  61 73 64 66 61 73 64 66  61 73 64 \x1b[32m61\x1b[0m \x1b[32m7c\x1b[0m \x1b[32m62\x1b[0m 61 73  |asdfasdfasd\x1b[32ma\x1b[0m\x1b[32m|\x1b[0m\x1b[32mb\x1b[0mas|\n" +
				"00000010  64 66 61 64 73 64 66 73  7c                       |dfadsdfs||\n"

		assert.Nil(t, err)
		assert.Equal(t, expected, result.String())
	})
}

func TestHighlight(t *testing.T) {
	const multiSnippetHighlightHexDumpResponse = "00000000  \x1b[32m61\x1b[0m \x1b[32m62\x1b[0m 63 \x1b[32m64\x1b[0m \x1b[32m65\x1b[0m \x1b[32m66\x1b[0m \x1b[32m67\x1b[0m \x1b[32m68\x1b[0m  \x1b[32m69\x1b[0m \x1b[32m6a\x1b[0m 6b 6c 6d 6e \x1b[32m61\x1b[0m \x1b[32m62\x1b[0m  |\x1b[32ma\x1b[0m\x1b[32mb\x1b[0mc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmn\x1b[32ma\x1b[0m\x1b[32mb\x1b[0m|\n" +
		"00000010  63 \x1b[32m64\x1b[0m \x1b[32m65\x1b[0m \x1b[32m66\x1b[0m \x1b[32m67\x1b[0m \x1b[32m68\x1b[0m \x1b[32m69\x1b[0m \x1b[32m6a\x1b[0m  6b 6c 6d 6e \x1b[32m61\x1b[0m \x1b[32m62\x1b[0m 63 \x1b[32m64\x1b[0m  |c\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmn\x1b[32ma\x1b[0m\x1b[32mb\x1b[0mc\x1b[32md\x1b[0m|\n" +
		"00000020  \x1b[32m65\x1b[0m \x1b[32m66\x1b[0m \x1b[32m67\x1b[0m \x1b[32m68\x1b[0m \x1b[32m69\x1b[0m \x1b[32m6a\x1b[0m 6b 6c  6d 6e \x1b[32m61\x1b[0m \x1b[32m62\x1b[0m 63 \x1b[32m64\x1b[0m \x1b[32m65\x1b[0m \x1b[32m66\x1b[0m  |\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmn\x1b[32ma\x1b[0m\x1b[32mb\x1b[0mc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m|\n" +
		"00000030  \x1b[32m67\x1b[0m \x1b[32m68\x1b[0m \x1b[32m69\x1b[0m \x1b[32m6a\x1b[0m 6b 6c 6d 6e  \x1b[32m61\x1b[0m \x1b[32m62\x1b[0m 63 \x1b[32m64\x1b[0m \x1b[32m65\x1b[0m \x1b[32m66\x1b[0m \x1b[32m67\x1b[0m \x1b[32m68\x1b[0m  |\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmn\x1b[32ma\x1b[0m\x1b[32mb\x1b[0mc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m|\n" +
		"00000040  \x1b[32m69\x1b[0m \x1b[32m6a\x1b[0m 6b 6c 6d 6e \x1b[32m61\x1b[0m \x1b[32m62\x1b[0m  63 \x1b[32m64\x1b[0m \x1b[32m65\x1b[0m \x1b[32m66\x1b[0m \x1b[32m67\x1b[0m \x1b[32m68\x1b[0m \x1b[32m69\x1b[0m \x1b[32m6a\x1b[0m  |\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmn\x1b[32ma\x1b[0m\x1b[32mb\x1b[0mc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0m|\n" +
		"00000050  6b 6c 6d 6e \x1b[32m61\x1b[0m \x1b[32m62\x1b[0m 63 \x1b[32m64\x1b[0m  \x1b[32m65\x1b[0m \x1b[32m66\x1b[0m \x1b[32m67\x1b[0m \x1b[32m68\x1b[0m \x1b[32m69\x1b[0m \x1b[32m6a\x1b[0m 6b 6c  |klmn\x1b[32ma\x1b[0m\x1b[32mb\x1b[0mc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mkl|\n" +
		"00000060  6d 6e \x1b[32m61\x1b[0m \x1b[32m62\x1b[0m 63 \x1b[32m64\x1b[0m \x1b[32m65\x1b[0m \x1b[32m66\x1b[0m  \x1b[32m67\x1b[0m \x1b[32m68\x1b[0m \x1b[32m69\x1b[0m \x1b[32m6a\x1b[0m 6b 6c 6d 6e  |mn\x1b[32ma\x1b[0m\x1b[32mb\x1b[0mc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmn|\n" +
		"00000070  \x1b[32m61\x1b[0m \x1b[32m62\x1b[0m 63 \x1b[32m64\x1b[0m \x1b[32m65\x1b[0m \x1b[32m66\x1b[0m \x1b[32m67\x1b[0m \x1b[32m68\x1b[0m  \x1b[32m69\x1b[0m \x1b[32m6a\x1b[0m 6b 6c 6d 6e        |\x1b[32ma\x1b[0m\x1b[32mb\x1b[0mc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmn|\n"

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
		expected :=
			"\x1b[32ma\x1b[0m\x1b[32mb\x1b[0mc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmn\x1b[32m" +
				"a\x1b[0m\x1b[32mb\x1b[0mc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmn\x1b[32m" +
				"a\x1b[0m\x1b[32mb\x1b[0mc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmn\x1b[32m" +
				"a\x1b[0m\x1b[32mb\x1b[0mc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmn\x1b[32m" +
				"a\x1b[0m\x1b[32mb\x1b[0mc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmn\x1b[32m" +
				"a\x1b[0m\x1b[32mb\x1b[0mc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmn\x1b[32m" +
				"a\x1b[0m\x1b[32mb\x1b[0mc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmn\x1b[32m" +
				"a\x1b[0m\x1b[32mb\x1b[0mc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmn\x1b[32m" +
				"a\x1b[0m\x1b[32mb\x1b[0mc\x1b[32md\x1b[0m\x1b[32me\x1b[0m\x1b[32mf\x1b[0m\x1b[32mg\x1b[0m\x1b[32mh\x1b[0m\x1b[32mi\x1b[0m\x1b[32mj\x1b[0mklmn"
		print(result)
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

func TestMultiSubstringMatchHighlight(t *testing.T) {
	const input = `
start ValueToMatch end
start ValueToMatch-1.2.3 end
start ValueToMatch-2.1 end 
`
	matches := map[string][]string{
		"first":  {"ValueToMatch"},
		"second": {"ValueToMatch-1.2.3"},
		"third":  {"ValueToMatch-2.1"},
	}
	operatorResult := operators.Result{Matches: matches}

	expected :=
		"\nstart \x1b[32mV\x1b[0m\x1b[32ma\x1b[0m\x1b[32ml\x1b[0m\x1b[32mu\x1b[0m\x1b[32me\x1b[0m\x1b[32mT\x1b[0m\x1b[32mo\x1b[0m\x1b[32mM\x1b[0m\x1b[32ma\x1b[0m\x1b[32mt\x1b[0m\x1b[32mc\x1b[0m\x1b[32mh\x1b[0m end\n" +
			"start \x1b[32mV\x1b[0m\x1b[32ma\x1b[0m\x1b[32ml\x1b[0m\x1b[32mu\x1b[0m\x1b[32me\x1b[0m\x1b[32mT\x1b[0m\x1b[32mo\x1b[0m\x1b[32mM\x1b[0m\x1b[32ma\x1b[0m\x1b[32mt\x1b[0m\x1b[32mc\x1b[0m\x1b[32mh\x1b[0m\x1b[32m-\x1b[0m\x1b[32m1\x1b[0m\x1b[32m.\x1b[0m\x1b[32m2\x1b[0m\x1b[32m.\x1b[0m\x1b[32m3\x1b[0m end\n" +
			"start \x1b[32mV\x1b[0m\x1b[32ma\x1b[0m\x1b[32ml\x1b[0m\x1b[32mu\x1b[0m\x1b[32me\x1b[0m\x1b[32mT\x1b[0m\x1b[32mo\x1b[0m\x1b[32mM\x1b[0m\x1b[32ma\x1b[0m\x1b[32mt\x1b[0m\x1b[32mc\x1b[0m\x1b[32mh\x1b[0m\x1b[32m-\x1b[0m\x1b[32m2\x1b[0m\x1b[32m.\x1b[0m\x1b[32m1\x1b[0m end \n"
	result := Highlight(&operatorResult, input, false, false)
	assert.Equal(t, expected, result)
}
