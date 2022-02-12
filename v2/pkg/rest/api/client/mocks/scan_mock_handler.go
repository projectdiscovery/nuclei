package mocks

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/golang/mock/gomock"
	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo/v4"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/api/handlers"
	scans2 "github.com/projectdiscovery/nuclei/v2/pkg/rest/api/services/scans"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/api/services/settings"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/api/services/targets"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/db"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/db/dbsql"
)

type ScanMockHandler struct {
	mockDb *db.MockQuerier
}

func NewScanMockHandler(mockParam *db.MockQuerier) ScanMockHandler {
	handler := ScanMockHandler{mockParam}
	return handler
}

func (m *ScanMockHandler) GetScans(c echo.Context) error {
	var r1 = []dbsql.Scan{{ID: 1, Name: "test1"}}
	m.mockDb.EXPECT().GetScans(gomock.Any()).Times(1).Return(r1, nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.GetScans(c)
}

func (m *ScanMockHandler) AddScan(c echo.Context) error {
	tempdir, _ := ioutil.TempDir("", "test-dir-*")
	defer os.RemoveAll(tempdir)
	targets := targets.NewTargetsStorage(tempdir)
	scans := scans2.NewScanService("", true, 1, m.mockDb, targets)
	server := handlers.New(m.mockDb, nil, scans)

	m.mockDb.EXPECT().AddScan(gomock.Any(), gomock.Any()).Times(1).Return(int64(1), nil)
	m.mockDb.EXPECT().GetSettingByName(gomock.Any(), gomock.Any()).Times(1).Return(dbsql.GetSettingByNameRow{Settingdata: settings.DefaultSettingsYAML, Datatype: "internal"}, nil)
	m.mockDb.EXPECT().GetTemplatesForScan(gomock.Any(), gomock.Any()).Times(1).Return([]dbsql.GetTemplatesForScanRow{{Path: "http-add-scan-test.yaml", Contents: templateContents}}, nil)
	m.mockDb.EXPECT().AddIssue(gomock.Any(), gomock.Any()).Times(1).Return(int64(1), nil)
	m.mockDb.EXPECT().UpdateScanState(gomock.Any(), gomock.Any()).Times(2).Return(nil)
	return server.AddScan(c)
}

func (m *ScanMockHandler) GetScanProgress(c echo.Context) error {
	tempdir, _ := ioutil.TempDir("", "test-dir-*")
	defer os.RemoveAll(tempdir)
	targets := targets.NewTargetsStorage(tempdir)
	scans := scans2.NewScanService("", true, 1, m.mockDb, targets)
	server := handlers.New(m.mockDb, nil, scans)
	return server.GetScanProgress(c)
}

func (m *ScanMockHandler) GetScan(c echo.Context) error {
	m.mockDb.EXPECT().GetScan(gomock.Any(), gomock.Any()).Times(1).Return(dbsql.Scan{Name: "test"}, nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.GetScan(c)
}

func (m *ScanMockHandler) UpdateScan(c echo.Context) error {
	tempdir, _ := ioutil.TempDir("", "test-dir-*")
	defer os.RemoveAll(tempdir)
	targets := targets.NewTargetsStorage(tempdir)
	scans := scans2.NewScanService("", true, 1, m.mockDb, targets)
	server := handlers.New(m.mockDb, nil, scans)
	m.mockDb.EXPECT().UpdateScanState(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	return server.UpdateScan(c)
}

func (m *ScanMockHandler) DeleteScan(c echo.Context) error {
	m.mockDb.EXPECT().DeleteIssueByScanID(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	m.mockDb.EXPECT().DeleteScan(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.DeleteScan(c)
}

func (m *ScanMockHandler) ExecuteScan(c echo.Context) error {
	tempdir, _ := ioutil.TempDir("", "test-dir-*")
	defer os.RemoveAll(tempdir)
	targets := targets.NewTargetsStorage(tempdir)
	scans := scans2.NewScanService("", true, 1, m.mockDb, targets)
	server := handlers.New(m.mockDb, nil, scans)
	return server.ExecuteScan(c)
}

func (m *ScanMockHandler) GetScanMatches(c echo.Context) error {
	var r1 = []dbsql.GetIssuesMatchesRow{{ID: 1, Templatename: "test1"}}
	m.mockDb.EXPECT().GetIssuesMatches(gomock.Any(), gomock.Any()).Times(1).Return(r1, nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.GetScanMatches(c)

}

type GetScanErrorsTestResponse struct {
	ID int64
}

func (m *ScanMockHandler) GetScanErrors(c echo.Context) error {
	bf := new(bytes.Buffer)
	_ = jsoniter.NewEncoder(bf).Encode([]GetScanErrorsTestResponse{{ID: 1}, {ID: 2}})
	scanID := c.Param("id")
	tempdir, _ := ioutil.TempDir("", "test-dir-*")
	_ = ioutil.WriteFile(filepath.Join(tempdir, scanID), bf.Bytes(), os.ModePerm)
	defer os.RemoveAll(tempdir)
	targets := targets.NewTargetsStorage(tempdir)
	scans := scans2.NewScanService(tempdir, true, 1, m.mockDb, targets)
	server := handlers.New(m.mockDb, nil, scans)
	return server.GetScanErrors(c)
}
