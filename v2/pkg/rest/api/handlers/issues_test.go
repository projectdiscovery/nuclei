package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo/v4"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/db"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/db/dbsql"
	"github.com/stretchr/testify/require"
)

func TestAddIssueHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var buf bytes.Buffer
	err := jsoniter.NewEncoder(&buf).Encode(&AddIssueRequest{})
	require.NoError(t, err, "could not json encode req")

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", &buf)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	querier := db.NewMockQuerier(ctrl)
	querier.EXPECT().
		AddIssue(gomock.Any(), gomock.Any()).
		Times(1).
		Return(int64(1), nil)

	server := New(querier, nil, nil)

	err = server.AddIssue(c)
	require.NoError(t, err, "could not add issue")
	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")
}

func TestGetIssuesHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	querier := db.NewMockQuerier(ctrl)
	querier.EXPECT().
		GetIssues(gomock.Any(), gomock.Any()).
		Times(1).
		Return([]dbsql.GetIssuesRow{{ID: 1}}, nil)

	server := New(querier, nil, nil)

	err := server.GetIssues(c)
	require.NoError(t, err, "could not get issues")
	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")
}

func TestGetIssueHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	c.SetPath("/:id")
	c.SetParamNames("id")
	c.SetParamValues("1")

	querier := db.NewMockQuerier(ctrl)
	querier.EXPECT().
		GetIssue(gomock.Any(), int64(1)).
		Times(1).
		Return(dbsql.GetIssueRow{ID: 1}, nil)

	server := New(querier, nil, nil)

	err := server.GetIssue(c)
	require.NoError(t, err, "could not get issue")
	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")
}

func TestUpdateIssueHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var buf bytes.Buffer
	err := jsoniter.NewEncoder(&buf).Encode(&UpdateIssueRequest{})
	require.NoError(t, err, "could not json encode req")

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", &buf)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	c.SetPath("/:id")
	c.SetParamNames("id")
	c.SetParamValues("1")

	querier := db.NewMockQuerier(ctrl)
	querier.EXPECT().
		UpdateIssue(gomock.Any(), gomock.Any()).
		Times(1).
		Return(nil)

	server := New(querier, nil, nil)

	err = server.UpdateIssue(c)
	require.NoError(t, err, "could not update issue")
	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")
}

func TestDeleteIssueHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	e := echo.New()
	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	c.SetPath("/:id")
	c.SetParamNames("id")
	c.SetParamValues("1")

	querier := db.NewMockQuerier(ctrl)
	querier.EXPECT().
		DeleteIssue(gomock.Any(), int64(1)).
		Times(1).
		Return(nil)

	server := New(querier, nil, nil)

	err := server.DeleteIssue(c)
	require.NoError(t, err, "could not delete issues")
	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")
}
