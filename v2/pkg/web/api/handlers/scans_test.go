package handlers

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/scans"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
	"github.com/stretchr/testify/require"
)

func TestGetScanErrorsHandler(t *testing.T) {
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
	tempDir, err := ioutil.TempDir("", "test-*")
	require.Nil(t, err, "could not create temporary directory")
	defer os.RemoveAll(tempDir)

	scanService := scans.NewScanService(tempDir, 1, querier, nil)
	writer, err := scanService.Logs.Write(1)
	require.NoError(t, err, "could not write scan error log")
	_, _ = writer.Write([]byte("test\ndata"))
	writer.Close()

	server := New(querier, nil, scanService)

	err = server.GetScanErrors(c)
	require.NoError(t, err, "could not get scan errors")
	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")

	data, _ := ioutil.ReadAll(rec.Result().Body)
	require.Equal(t, "test\ndata", string(data), "could not get correct logs")
}

func TestGetScanProgressHandler(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	scanService := scans.NewScanService("", 1, nil, nil)
	server := New(nil, nil, scanService)
	scanService.Running.Store(int64(1), scans.PercentReturnFunc(func() float64 {
		return 10.0
	}))
	err := server.GetScanProgress(c)
	require.NoError(t, err, "could not get scan errors")

	data, _ := ioutil.ReadAll(rec.Result().Body)
	require.Equal(t, `{"1":10}`, strings.TrimSuffix(string(data), "\n"), "could not get correct progress")
}
