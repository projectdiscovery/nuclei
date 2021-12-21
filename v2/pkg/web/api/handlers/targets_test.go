package handlers

import (
	"bytes"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/targets"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
	"github.com/stretchr/testify/require"
)

func TestAddTargetHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("path", "test.txt")
	writer.WriteField("name", "test.txt")

	file, err := writer.CreateFormFile("contents", "test.txt")
	require.NoError(t, err, "could not create form file")
	_, _ = file.Write([]byte("https://example.com"))
	_ = writer.Close()

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", &buf)
	req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	querier := db.NewMockQuerier(ctrl)
	querier.EXPECT().
		AddTarget(gomock.Any(), gomock.Any()).
		Times(1).
		Return(int64(1), nil)

	tempDir, err := ioutil.TempDir("", "test-*")
	require.Nil(t, err, "could not create temporary directory")
	defer os.RemoveAll(tempDir)

	targetsStorage := targets.NewTargetsStorage(tempDir)
	server := New(querier, targetsStorage, nil)

	err = server.AddTarget(c)
	require.NoError(t, err, "could not add target")

	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")

	files, _ := ioutil.ReadDir(tempDir)
	data, err := ioutil.ReadFile(path.Join(tempDir, files[0].Name()))
	require.NoError(t, err, "could not read target")
	require.Equal(t, "https://example.com", string(data), "could not read target file")
}

func TestUpdateTargetHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("path", "test.txt")
	writer.WriteField("name", "test.txt")

	file, err := writer.CreateFormFile("contents", "test.txt")
	require.NoError(t, err, "could not create form file")
	_, _ = file.Write([]byte("https://example.com"))
	_ = writer.Close()

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", &buf)
	req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	querier := db.NewMockQuerier(ctrl)
	querier.EXPECT().
		AddTarget(gomock.Any(), gomock.Any()).
		Times(1).
		Return(int64(1), nil)

	tempDir, err := ioutil.TempDir("", "test-*")
	require.Nil(t, err, "could not create temporary directory")
	defer os.RemoveAll(tempDir)

	targetsStorage := targets.NewTargetsStorage(tempDir)
	server := New(querier, targetsStorage, nil)

	err = server.AddTarget(c)
	require.NoError(t, err, "could not add target")
	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")

	files, _ := ioutil.ReadDir(tempDir)

	buf.Reset()

	writer = multipart.NewWriter(&buf)
	writer.WriteField("id", files[0].Name())

	file, err = writer.CreateFormFile("contents", "test.txt")
	require.NoError(t, err, "could not create form file")
	_, _ = file.Write([]byte("https://test.com"))
	_ = writer.Close()

	e = echo.New()
	req = httptest.NewRequest(http.MethodPut, "/", &buf)
	req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)

	c.SetPath("/:id")
	c.SetParamNames("id")
	c.SetParamValues("1")

	querier.EXPECT().
		UpdateTargetMetadata(gomock.Any(), gomock.Eq(dbsql.UpdateTargetMetadataParams{Total: 1, ID: 1})).
		Times(1).
		Return(nil)

	err = server.UpdateTarget(c)
	require.NoError(t, err, "could not update target")
	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")

	data, err := ioutil.ReadFile(path.Join(tempDir, files[0].Name()))
	require.NoError(t, err, "could not read target")
	require.Equal(t, "https://example.com\nhttps://test.com", string(data), "could not read target file")
}

func TestDeleteTargetHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("path", "test.txt")
	writer.WriteField("name", "test.txt")

	file, err := writer.CreateFormFile("contents", "test.txt")
	require.NoError(t, err, "could not create form file")
	_, _ = file.Write([]byte("https://example.com"))
	_ = writer.Close()

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", &buf)
	req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	querier := db.NewMockQuerier(ctrl)
	querier.EXPECT().
		AddTarget(gomock.Any(), gomock.Any()).
		Times(1).
		Return(int64(1), nil)

	tempDir, err := ioutil.TempDir("", "test-*")
	require.Nil(t, err, "could not create temporary directory")
	defer os.RemoveAll(tempDir)

	targetsStorage := targets.NewTargetsStorage(tempDir)
	server := New(querier, targetsStorage, nil)

	err = server.AddTarget(c)
	require.NoError(t, err, "could not add target")
	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")

	files, _ := ioutil.ReadDir(tempDir)

	e = echo.New()
	req = httptest.NewRequest(http.MethodDelete, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)

	c.SetPath("/:id")
	c.SetParamNames("id")
	c.SetParamValues("1")

	parsedID := int64(1)
	querier.EXPECT().
		DeleteTarget(gomock.Any(), gomock.Eq(parsedID)).
		Times(1).
		Return(nil)
	querier.EXPECT().
		GetTarget(gomock.Any(), gomock.Eq(parsedID)).
		Times(1).
		Return(dbsql.GetTargetRow{Internalid: files[0].Name()}, nil)

	err = server.DeleteTarget(c)
	require.NoError(t, err, "could not delete target")
	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")

	_, err = ioutil.ReadFile(path.Join(tempDir, files[0].Name()))
	require.Error(t, err, "could read target after deletion")
}

func TestGetTargetContentsHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("path", "test.txt")
	writer.WriteField("name", "test.txt")

	file, err := writer.CreateFormFile("contents", "test.txt")
	require.NoError(t, err, "could not create form file")
	_, _ = file.Write([]byte("https://example.com"))
	_ = writer.Close()

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", &buf)
	req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	querier := db.NewMockQuerier(ctrl)
	querier.EXPECT().
		AddTarget(gomock.Any(), gomock.Any()).
		Times(1).
		Return(int64(1), nil)

	tempDir, err := ioutil.TempDir("", "test-*")
	require.Nil(t, err, "could not create temporary directory")
	defer os.RemoveAll(tempDir)

	targetsStorage := targets.NewTargetsStorage(tempDir)
	server := New(querier, targetsStorage, nil)

	err = server.AddTarget(c)
	require.NoError(t, err, "could not add target")
	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")

	files, _ := ioutil.ReadDir(tempDir)

	e = echo.New()
	req = httptest.NewRequest(http.MethodDelete, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)

	c.SetPath("/:id")
	c.SetParamNames("id")
	c.SetParamValues("1")

	parsedID := int64(1)
	querier.EXPECT().
		GetTarget(gomock.Any(), gomock.Eq(parsedID)).
		Times(1).
		Return(dbsql.GetTargetRow{Internalid: files[0].Name()}, nil)

	err = server.GetTargetContents(c)
	require.NoError(t, err, "could not delete target")
	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")

	data, err := ioutil.ReadFile(path.Join(tempDir, files[0].Name()))
	require.NoError(t, err, "could not read target")
	require.Equal(t, "https://example.com", string(data), "could not read target file")
}
