package protocolstate

import (
	"context"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestInit(t *testing.T) {
	err := Init(&types.Options{})
	require.NoError(t, err, "could not init dialer")

	_, err = Dialer.Dial(context.Background(), "tcp", "127.0.0.1:443")
	require.Error(t, err, "could dial restricted ip")
}
