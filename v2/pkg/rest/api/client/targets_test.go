package client

import (
	"io/ioutil"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/rest/api/client/mocks"
	"github.com/stretchr/testify/require"
)

func TestTarget(t *testing.T) {
	setup := mocks.NewMockHttpServer(t)
	defer setup()
	client := New(WithToken("test"))
	svc := TargetsService{Client: client}
	reader := strings.NewReader("example.com")
	var targetID int64 = 1
	t.Run("AddTarget", func(t *testing.T) {
		resp, err := svc.AddTarget(AddTargetRequest{
			Name:     "targets",
			Path:     "test",
			Contents: reader,
		})
		targetID = resp
		require.NoError(t, err, "could not add target")
		require.Greater(t, resp, int64(0))
	})
	t.Run("GetTargets", func(t *testing.T) {
		resp, err := svc.GetTargets(GetTargetsRequest{})
		require.NoError(t, err, "could not get targets")
		require.NotEmpty(t, resp)
	})
	t.Run("GetTargetContents", func(t *testing.T) {
		resp, err := svc.GetTargetContents(targetID)
		require.NoError(t, err, "could not get target contents")
		content, _ := ioutil.ReadAll(resp)
		require.NotEmpty(t, string(content))
	})
	t.Run("UpdateTarget", func(t *testing.T) {
		newReader := strings.NewReader("test.com")

		err := svc.UpdateTarget(UpdateTargetRequest{
			ID:       targetID,
			Contents: newReader,
		})
		require.NoError(t, err, "could not update target")
	})
	t.Run("DeleteTarget", func(t *testing.T) {
		err := svc.DeleteTarget(targetID)
		require.NoError(t, err, "could not delete target")
	})
}
