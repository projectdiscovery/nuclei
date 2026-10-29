package hash

import (
	"testing"

	"github.com/projectdiscovery/dsl"
	"github.com/stretchr/testify/require"
)

func TestSumMatchesDSLAcrossChunks(t *testing.T) {
	data := make([]byte, 3<<20+7)
	for i := range data {
		data[i] = byte(i * 31)
	}
	for _, algorithm := range []string{"md5", "sha1", "sha256", "sha512", "mmh3"} {
		t.Run(algorithm, func(t *testing.T) {
			h, err := New(algorithm)
			require.NoError(t, err)
			for chunk := data; len(chunk) > 0; {
				n := min(len(chunk), 65521)
				require.NoError(t, h.Write(chunk[:n]))
				chunk = chunk[n:]
			}
			want, err := dsl.EvalExpr(algorithm+"(body)", map[string]interface{}{"body": string(data)})
			require.NoError(t, err)
			sum, err := h.Sum()
			require.NoError(t, err)
			require.Equal(t, want, sum)
		})
	}
}

func TestNewRejectsUnknownAlgorithm(t *testing.T) {
	_, err := New("crc32")
	require.Error(t, err)
}

func TestHashNotCreatedByNewErrors(t *testing.T) {
	var h Hash
	require.ErrorIs(t, h.WriteString("x"), errNotCreatedByNew)
	_, err := h.Sum()
	require.ErrorIs(t, err, errNotCreatedByNew)
}
