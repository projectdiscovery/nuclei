package handlers

import (
	"bytes"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo/v4"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
	"github.com/stretchr/testify/require"
)

func TestAddTemplateHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jsonBody := AddTemplateRequest{
		Contents: "test-contents",
		Path:     "template.yaml",
	}
	var buf bytes.Buffer
	_ = jsoniter.NewEncoder(&buf).Encode(&jsonBody)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", &buf)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	querier := db.NewMockQuerier(ctrl)
	querier.EXPECT().
		AddTemplate(gomock.Any(), gomock.Any()).
		Times(1).
		Return(int64(1), nil)

	server := New(querier, nil, nil)

	err := server.AddTemplate(c)
	require.NoError(t, err, "could not add template")

	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")
}

func TestUpdateTemplateHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jsonBody := UpdateTemplateRequest{
		Contents: "test-contents",
		Path:     "template.yaml",
	}
	var buf bytes.Buffer
	_ = jsoniter.NewEncoder(&buf).Encode(&jsonBody)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPut, "/", &buf)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	querier := db.NewMockQuerier(ctrl)
	querier.EXPECT().
		UpdateTemplate(gomock.Any(), gomock.Any()).
		Times(1).
		Return(nil)

	server := New(querier, nil, nil)

	err := server.UpdateTemplate(c)
	require.NoError(t, err, "could not update template")

	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")
}

func TestDeleteTemplateHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jsonBody := DeleteTemplateRequest{
		Path: "template.yaml",
	}
	var buf bytes.Buffer
	_ = jsoniter.NewEncoder(&buf).Encode(&jsonBody)

	e := echo.New()
	req := httptest.NewRequest(http.MethodDelete, "/", &buf)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	querier := db.NewMockQuerier(ctrl)
	querier.EXPECT().
		DeleteTemplate(gomock.Any(), gomock.Any()).
		Times(1).
		Return(nil)

	server := New(querier, nil, nil)

	err := server.DeleteTemplate(c)
	require.NoError(t, err, "could not delete template")

	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")
}

func TestGetTemplatesRawHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/?path=test.yaml", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	querier := db.NewMockQuerier(ctrl)
	querier.EXPECT().
		GetTemplateContents(gomock.Any(), gomock.Eq("test.yaml")).
		Times(1).
		Return("test-contents", nil)

	server := New(querier, nil, nil)

	err := server.GetTemplatesRaw(c)
	require.NoError(t, err, "could not get raw template")

	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")
	data, _ := ioutil.ReadAll(rec.Result().Body)
	require.Equal(t, "test-contents", string(data), "could not get correct response body")
}

func TestExecuteTemplateHandler(t *testing.T) {
	_ = protocolinit.Init(testutils.DefaultOptions)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tcpserver := testutils.NewTCPServer(func(conn net.Conn) {
		_, _ = conn.Write([]byte("test"))
		conn.Close()
	})
	defer tcpserver.Close()

	const testTemplate = `
id: test-template
info:
  name: test-template
  author: pdteam
  severity: info
network:
  - host: 
      - "{{Hostname}}"
    matchers:
      - type: word
        words:
          - "test"
        part: raw`

	jsonBody := ExecuteTemplateRequest{
		Path:   "template.yaml",
		Target: tcpserver.URL,
	}
	var buf bytes.Buffer
	_ = jsoniter.NewEncoder(&buf).Encode(&jsonBody)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", &buf)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	querier := db.NewMockQuerier(ctrl)
	querier.EXPECT().
		GetTemplateContents(gomock.Any(), gomock.Eq("template.yaml")).
		Times(1).
		Return(testTemplate, nil)

	server := New(querier, nil, nil)

	err := server.ExecuteTemplate(c)
	require.NoError(t, err, "could not execute template")

	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")
	data, _ := ioutil.ReadAll(rec.Result().Body)
	require.Contains(t, string(data), `,"debug":{"":"test"}}`, "could not get correct response body")
}
