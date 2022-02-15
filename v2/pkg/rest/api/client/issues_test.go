package client

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/rest/api/client/mocks"
	"github.com/stretchr/testify/require"
)

func TestIssues(t *testing.T) {
	setup := mocks.NewMockHttpServer(t)
	defer setup()
	client := New(WithToken("test"))
	svc := IssuesService{Client: client}
	var issueID int64
	t.Run("AddIssue", func(t *testing.T) {
		resp, err := svc.AddIssue(AddIssueRequest{
			ScanID: 1,
		})
		require.NoError(t, err, "could not add issue")
		require.Greater(t, resp, int64(0))
		issueID = resp
	})
	t.Run("GetIssues", func(t *testing.T) {
		resp, err := svc.GetIssues(GetIssuesRequest{
			Search: "issues.txt",
		})
		require.NoError(t, err, "could not get issues")
		require.GreaterOrEqual(t, len(resp), 0)
	})
	t.Run("GetIssue", func(t *testing.T) {
		resp, err := svc.GetIssue(issueID)
		require.NoError(t, err, "could not get issues")
		require.NotNil(t, resp)
	})
	t.Run("UpdateIssues", func(t *testing.T) {
		err := svc.UpdateIssue(issueID, UpdateIssueRequest{State: "Closed"})
		require.NoError(t, err, "could not update issue")
	})
	t.Run("DeleteIssues", func(t *testing.T) {
		svc := IssuesService{Client: client}
		err := svc.DeleteIssue(issueID)
		require.NoError(t, err, "could not delete issue")
	})
}
