package ssti

import (
	"strconv"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/stretchr/testify/require"
)

func TestAnalyzerRegistered(t *testing.T) {
	require.NotNil(t, analyzers.GetAnalyzer("ssti"), "ssti analyzer must be registered")
	require.Equal(t, "ssti", (&Analyzer{}).Name())
}

func TestGenerateProbes(t *testing.T) {
	const (
		a     = 31
		b     = 1337
		start = "sAAAA"
		end   = "sBBBB"
	)
	probes := GenerateProbes(a, b, start, end)
	require.NotEmpty(t, probes)

	expr := "31*1337"
	for _, p := range probes {
		require.NotEmpty(t, p.Engine)
		// every payload must carry the raw arithmetic expression and both sentinels
		require.Contains(t, p.Payload, expr, "probe %q must contain the expression", p.Engine)
		require.True(t, strings.HasPrefix(p.Payload, start), "probe %q must start with sentinel", p.Engine)
		require.True(t, strings.HasSuffix(p.Payload, end), "probe %q must end with sentinel", p.Engine)
		// the unevaluated payload must NOT contain the product (avoids self-match)
		require.NotContains(t, p.Payload, strconv.Itoa(a*b))
	}

	// sanity: well-known syntaxes are present
	var syntaxes []string
	for _, p := range probes {
		syntaxes = append(syntaxes, p.Payload)
	}
	joined := strings.Join(syntaxes, "\n")
	require.Contains(t, joined, "${31*1337}")
	require.Contains(t, joined, "{{31*1337}}")
	require.Contains(t, joined, "#{31*1337}")
}

func TestDetectEvaluation(t *testing.T) {
	const (
		start   = "sXYZ12"
		end     = "sQRS98"
		product = 1849 // 43*43
	)

	t.Run("evaluated product between sentinels is detected", func(t *testing.T) {
		body := "<html>result: " + start + strconv.Itoa(product) + end + " done</html>"
		require.True(t, DetectEvaluation(body, start, end, product))
	})

	t.Run("reflected unevaluated expression is NOT a hit", func(t *testing.T) {
		// the engine did not evaluate, so the literal expression survives
		body := "<html>result: " + start + "43*43" + end + " done</html>"
		require.False(t, DetectEvaluation(body, start, end, product))
	})

	t.Run("product without sentinels is NOT a hit", func(t *testing.T) {
		// product appears naturally elsewhere (e.g. a price) but not between sentinels
		body := "<html>total is 1849 dollars</html>"
		require.False(t, DetectEvaluation(body, start, end, product))
	})

	t.Run("product with only one sentinel is NOT a hit", func(t *testing.T) {
		body := start + strconv.Itoa(product) + "DIFFERENT"
		require.False(t, DetectEvaluation(body, start, end, product))
	})

	t.Run("empty inputs are safe", func(t *testing.T) {
		require.False(t, DetectEvaluation("", start, end, product))
		require.False(t, DetectEvaluation("body", "", end, product))
		require.False(t, DetectEvaluation("body", start, "", product))
	})
}

func TestRandTokenIsAlphabetic(t *testing.T) {
	for i := 0; i < 100; i++ {
		tok := randToken()
		require.NotEmpty(t, tok)
		for _, r := range tok {
			require.True(t, r >= 'a' && r <= 'z', "token must be lowercase alphabetic, got %q", tok)
		}
	}
	// two tokens should differ (extremely high probability)
	require.NotEqual(t, randToken(), randToken())
}
