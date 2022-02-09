package client

import (
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTarget(t *testing.T) {
	setup := NewMockHttpServer(t)
	defer setup()
	client := New(WithBasicAuth("user", "pass"))
	svc := TargetsService{Client: client}
	reader := strings.NewReader("example")
	var targetID int64 = 1
	t.Run("AddTarget", func(t *testing.T) {
		resp, err := svc.AddTarget(AddTargetRequest{
			Name:     "targets",
			Path:     "example.yaml",
			Contents: reader,
		})
		targetID = resp
		require.NoError(t, err, "could not add target")
		require.Greater(t, resp, int64(0))
	})
	t.Run("GetTarget", func(t *testing.T) {
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
		err := svc.UpdateTarget(UpdateTargetRequest{
			ID:       targetID,
			TargetID: fmt.Sprint(targetID),
			Contents: reader,
		})
		require.NoError(t, err, "could not update target")
	})
	t.Run("DeleteTarget", func(t *testing.T) {
		err := svc.DeleteTarget(targetID)
		require.NoError(t, err, "could not delete target")
	})
}
