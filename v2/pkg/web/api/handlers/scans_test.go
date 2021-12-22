package handlers

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo/v4"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/scans"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/settings"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/targets"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
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
	scanService.Running.Store(int64(1), &scans.RunningScan{
		ProgressFunc: scans.PercentReturnFunc(func() float64 {
			return 10.0
		}),
	})

	err := server.GetScanProgress(c)
	require.NoError(t, err, "could not get scan errors")

	data, _ := ioutil.ReadAll(rec.Result().Body)
	require.Equal(t, `{"1":10}`, strings.TrimSuffix(string(data), "\n"), "could not get correct progress")
}

func TestAddScanHandler(t *testing.T) {
	_ = protocolinit.Init(types.DefaultOptions())

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testserver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("Example Domain"))
	}))
	defer testserver.Close()

	const templateContents = `id: basic-example
info:
  name: Test HTTP Template
  author: pdteam
  severity: info

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "Example Domain"`

	scanRequest := AddScanRequest{
		Name:      "test-scan",
		Templates: []string{"http-add-scan-test.yaml"},
		Targets:   []string{"https://deadnxdomaintest.com", testserver.URL},
		Config:    "default",
		RunNow:    true,
	}
	var buf bytes.Buffer
	_ = jsoniter.NewEncoder(&buf).Encode(scanRequest)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", &buf)
	req.Header.Set("Content-Type", echo.MIMEApplicationJSONCharsetUTF8)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	var settingbuf bytes.Buffer
	defaultSettings := settings.DefaultSettings()
	_ = yaml.NewEncoder(&settingbuf).Encode(defaultSettings)

	querier := db.NewMockQuerier(ctrl)
	querier.EXPECT().
		AddScan(gomock.Any(), gomock.Any()).
		Times(1).
		Return(int64(1), nil)
	querier.EXPECT().
		GetSettingByName(gomock.Any(), gomock.Eq("default")).
		Times(1).
		Return(dbsql.GetSettingByNameRow{Settingdata: settingbuf.String(), Datatype: string(SettingTypeInternal)}, nil)
	querier.EXPECT().
		GetTemplatesForScan(gomock.Any(), gomock.Any()).
		Times(1).
		Return([]dbsql.GetTemplatesForScanRow{{Path: "http-add-scan-test.yaml", Contents: templateContents}}, nil)
	querier.EXPECT().
		AddIssue(gomock.Any(), gomock.Any()).
		Times(1).
		Return(int64(1), nil)

	tempDir, err := ioutil.TempDir("", "test-*")
	require.Nil(t, err, "could not create temporary directory")
	defer os.RemoveAll(tempDir)

	targetsService := targets.NewTargetsStorage(tempDir)
	scanService := scans.NewScanService(tempDir, 1, querier, targetsService)
	server := New(querier, targetsService, scanService)

	err = server.AddScan(c)
	require.NoError(t, err, "could not add scan")
	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")

	scanID := <-server.scans.Finished // wait for a finished scan

	t.Run("error-logs", func(t *testing.T) {
		logs, err := scanService.Logs.Read(scanID)
		require.NoError(t, err, "could not read scan logs")

		data, _ := ioutil.ReadAll(logs)
		logs.Close()

		require.NotEmpty(t, string(data), "could not get scan error logs")
	})
}
