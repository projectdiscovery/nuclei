package targets

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTargetsNewLineCountWriter(t *testing.T) {
	writer := &NewLineCountWriter{}
	writer.Write([]byte("test\ntest2\n"))
	require.Equal(t, int64(2), writer.Total, "could not get total newline writes")
}
