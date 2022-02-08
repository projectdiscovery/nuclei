package client

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetIssues(t *testing.T) {
	setup := NewMockHttpServer(t)
	defer setup()
	client := New(WithBasicAuth("user", "pass"))
	svc := IssuesService{Client: client}
	resp, err := svc.GetIssues(GetIssuesRequest{
		Search: "issues.txt",
	})
	require.NoError(t, err, "could not get issues")
	require.GreaterOrEqual(t, len(resp), 0)

}

func TestAddIssue(t *testing.T) {
	setup := NewMockHttpServer(t)
	defer setup()
	client := New(WithBasicAuth("user", "pass"))
	svc := IssuesService{Client: client}
	resp, err := svc.AddIssue(AddIssueRequest{
		ScanID: 1,
	})
	require.NoError(t, err, "could not add issue")
	require.Greater(t, resp, int64(0))
}

func TestUpdateIssue(t *testing.T) {
	setup := NewMockHttpServer(t)
	defer setup()
	//takes two parameters
	//client := New(WithBasicAuth("user", "pass"))
	//svc := IssuesService{Client: client}
	// err := svc.UpdateIssue({
	// 	ScanID: 1,
	// })
	// require.NoError(t, err, "could not add issue")
	// //require.Greater(t, resp, 0)

}

func TestDeleteIssue(t *testing.T) {
	setup := NewMockHttpServer(t)
	defer setup()
	client := New(WithBasicAuth("user", "pass"))
	svc := IssuesService{Client: client}
	err := svc.DeleteIssue(1)
	require.NoError(t, err, "could not delete issue")
}

func TestGetIssue(t *testing.T) {
	setup := NewMockHttpServer(t)
	defer setup()
	// //no get issue req struct
	client := New(WithBasicAuth("user", "pass"))
	svc := IssuesService{Client: client}
	resp, err := svc.GetIssue(1)
	require.NoError(t, err, "could not get issues")
	require.Greater(t, resp, int64(0))
}
