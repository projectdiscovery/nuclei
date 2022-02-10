package client

import (
	"bytes"
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo/v4"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/handlers"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/scans"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/settings"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/targets"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
)

type MockApiHandler struct {
	mockDb    *db.MockQuerier
	ctrl      *gomock.Controller
	scans     ScanMockHandler
	settings  SettingsMockHandler
	issues    IssuesMockHandler
	templates TemplateMockHandler
	targets   TargetsMockHandler
}

func NewMockApiHandler(t *testing.T) MockApiHandler {
	handler := MockApiHandler{}
	handler.ctrl = gomock.NewController(t)
	mockObject := db.NewMockQuerier(handler.ctrl)
	handler.mockDb = mockObject
	handler.scans = NewScanMockHandler(mockObject)
	handler.templates = NewTemplateMockHandler(mockObject)
	handler.targets = NewTargetsMockHandler(mockObject)
	handler.issues = NewIssuesMockHandler(mockObject)
	handler.settings = NewSettingsMockHandler(mockObject)
	return handler
}
func (m *MockApiHandler) Finish() {
	m.ctrl.Finish()
}

func NewMockHttpServer(t *testing.T) func() {
	ctx := context.Background()
	handler := NewMockApiHandler(t)
	e := echo.New()
	e.HideBanner = true
	apiGroup := e.Group("/api/v1")
	apiGroup.GET("/templates", handler.templates.GetTemplates)
	apiGroup.POST("/templates", handler.templates.AddTemplate)
	apiGroup.PUT("/templates", handler.templates.UpdateTemplate)
	apiGroup.DELETE("/templates", handler.templates.DeleteTemplate)
	apiGroup.GET("/templates/raw", handler.templates.GetTemplatesRaw)
	apiGroup.POST("/templates/execute", handler.templates.ExecuteTemplate)
	//targets
	apiGroup.GET("/targets", handler.targets.GetTargets)
	apiGroup.POST("/targets", handler.targets.AddTarget)
	apiGroup.PUT("/targets/:id", handler.targets.UpdateTarget)
	apiGroup.DELETE("/targets/:id", handler.targets.DeleteTarget)
	apiGroup.GET("/targets/:id", handler.targets.GetTargetContents)
	//settings
	apiGroup.GET("/settings", handler.settings.GetSettings)
	apiGroup.POST("/settings", handler.settings.SetSetting)
	apiGroup.GET("/settings/:name", handler.settings.GetSetting)
	apiGroup.PUT("/settings/:name", handler.settings.UpdateSettingByName)
	//scans
	apiGroup.GET("/scans", handler.scans.GetScans)
	apiGroup.POST("/scans", handler.scans.AddScan)
	apiGroup.GET("/scans/progress", handler.scans.GetScanProgress)
	apiGroup.GET("/scans/:id", handler.scans.GetScan)
	apiGroup.PUT("/scans/:id", handler.scans.UpdateScan)
	apiGroup.DELETE("/scans/:id", handler.scans.DeleteScan)
	apiGroup.GET("/scans/:id/execute", handler.scans.ExecuteScan)
	apiGroup.GET("/scans/:id/matches", handler.scans.GetScanMatches)
	apiGroup.GET("/scans/:id/errors", handler.scans.GetScanErrors)
	//issues
	apiGroup.GET("/issues", handler.issues.GetIssues)
	apiGroup.POST("/issues", handler.issues.AddIssue)
	apiGroup.GET("/issues/:id", handler.issues.GetIssue)
	apiGroup.PUT("/issues/:id", handler.issues.UpdateIssue)
	apiGroup.DELETE("/issues/:id", handler.issues.DeleteIssue)

	go e.Start(":8822")
	return func() {
		handler.Finish()
		e.Shutdown(ctx)
	}
}

type IssuesMockHandler struct {
	mockDb *db.MockQuerier
}

func NewIssuesMockHandler(mockParam *db.MockQuerier) IssuesMockHandler {
	handler := IssuesMockHandler{mockParam}
	return handler
}
func (m *IssuesMockHandler) GetIssues(c echo.Context) error {
	var r = []dbsql.GetIssuesRow{dbsql.GetIssuesRow{ID: 1}}
	m.mockDb.EXPECT().GetIssues(gomock.Any()).Times(1).Return(r, nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.GetIssues(c)
}

func (m *IssuesMockHandler) AddIssue(c echo.Context) error {
	m.mockDb.EXPECT().AddIssue(gomock.Any(), gomock.Any()).
		Times(1).
		Return(int64(1), nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.AddIssue(c)
}

func (m *IssuesMockHandler) UpdateIssue(c echo.Context) error {
	m.mockDb.EXPECT().UpdateIssue(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.UpdateIssue(c)
}

func (m *IssuesMockHandler) DeleteIssue(c echo.Context) error {
	m.mockDb.EXPECT().DeleteIssue(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.DeleteIssue(c)
}

func (m *IssuesMockHandler) GetIssue(c echo.Context) error {
	m.mockDb.EXPECT().GetIssue(gomock.Any(), gomock.Any()).Times(1).Return(dbsql.GetIssueRow{ID: 1}, nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.GetIssue(c)
}

type ScanMockHandler struct {
	mockDb *db.MockQuerier
}

func NewScanMockHandler(mockParam *db.MockQuerier) ScanMockHandler {
	handler := ScanMockHandler{mockParam}
	return handler
}

func (m *ScanMockHandler) GetScans(c echo.Context) error {
	var r1 = []dbsql.Scan{dbsql.Scan{ID: 1, Name: "test1"}}
	//	m.mockDb.EXPECT().GetScans(gomock.Any()).Times(1).Return(r1, nil)
	m.mockDb.EXPECT().GetScansBySearchKey(gomock.Any(), gomock.Any()).Times(1).Return(r1, nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.GetScans(c)
}

func (m *ScanMockHandler) AddScan(c echo.Context) error {
	tempdir, _ := ioutil.TempDir("", "test-dir-*")
	defer os.RemoveAll(tempdir)
	targets := targets.NewTargetsStorage(tempdir)
	scans := scans.NewScanService("", true, 1, m.mockDb, targets)
	server := handlers.New(m.mockDb, nil, scans)
	var schedules = []dbsql.GetScansForScheduleRow{{Name: "test-scan", ID: 1}}
	m.mockDb.EXPECT().GetSettingByName(gomock.Any(), gomock.Any()).Times(1).Return(dbsql.GetSettingByNameRow{}, nil)
	m.mockDb.EXPECT().GetScansForSchedule(gomock.Any(), gomock.Any()).Times(2).Return(schedules, nil)
	m.mockDb.EXPECT().UpdateScanState(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	m.mockDb.EXPECT().AddScan(gomock.Any(), gomock.Any()).
		Times(1).
		Return(int64(1), nil)

	return server.AddScan(c)
}

func (m *ScanMockHandler) GetScanProgress(c echo.Context) error {
	tempdir, _ := ioutil.TempDir("", "test-dir-*")
	defer os.RemoveAll(tempdir)
	targets := targets.NewTargetsStorage(tempdir)
	scans := scans.NewScanService("", true, 1, m.mockDb, targets)
	server := handlers.New(m.mockDb, nil, scans)
	var schedules = []dbsql.GetScansForScheduleRow{{Name: "test-scan", ID: 1}}
	m.mockDb.EXPECT().GetSettingByName(gomock.Any(), gomock.Any()).Times(1).Return(dbsql.GetSettingByNameRow{}, nil)
	m.mockDb.EXPECT().GetScansForSchedule(gomock.Any(), gomock.Any()).Times(2).Return(schedules, nil)
	m.mockDb.EXPECT().UpdateScanState(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	return server.GetScanProgress(c)
}

func (m *ScanMockHandler) GetScan(c echo.Context) error {
	m.mockDb.EXPECT().GetScan(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.GetScan(c)
}

func (m *ScanMockHandler) UpdateScan(c echo.Context) error {
	tempdir, _ := ioutil.TempDir("", "test-dir-*")
	defer os.RemoveAll(tempdir)
	targets := targets.NewTargetsStorage(tempdir)
	scans := scans.NewScanService("", true, 1, m.mockDb, targets)
	server := handlers.New(m.mockDb, nil, scans)
	m.mockDb.EXPECT().GetSettingByName(gomock.Any(), gomock.Any()).Times(1).Return(dbsql.GetSettingByNameRow{Settingdata: settings.DefaultSettingsYAML, Datatype: "internal"}, nil)
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
	scans := scans.NewScanService("", true, 1, m.mockDb, targets)
	server := handlers.New(m.mockDb, nil, scans)
	r := dbsql.Scan{
		ID:   1,
		Name: "test-scan",
	}
	m.mockDb.EXPECT().GetSettingByName(gomock.Any(), gomock.Any()).Times(1).Return(dbsql.GetSettingByNameRow{Settingdata: settings.DefaultSettingsYAML, Datatype: "internal"}, nil)
	m.mockDb.EXPECT().UpdateScanState(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	m.mockDb.EXPECT().GetScan(gomock.Any(), gomock.Any()).Times(1).Return(r, nil)
	return server.ExecuteScan(c)

}

func (m *ScanMockHandler) GetScanMatches(c echo.Context) error {
	var r1 = []dbsql.GetIssuesMatchesRow{{ID: 1, Templatename: "test1"}}
	m.mockDb.EXPECT().GetIssuesMatches(gomock.Any(), gomock.Any()).Times(1).Return(r1, nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.GetScanMatches(c)

}

func (m *ScanMockHandler) GetScanErrors(c echo.Context) error {
	bf := new(bytes.Buffer)
	jsoniter.NewEncoder(bf).Encode([]GetScanErrorsResponse{{ID: 1}, {ID: 2}})
	scanID := c.Param("id")
	tempdir, _ := ioutil.TempDir("", "test-dir-*")
	ioutil.WriteFile(filepath.Join(tempdir, scanID), bf.Bytes(), os.ModePerm)
	defer os.RemoveAll(tempdir)
	targets := targets.NewTargetsStorage(tempdir)
	scans := scans.NewScanService(tempdir, true, 1, m.mockDb, targets)
	server := handlers.New(m.mockDb, nil, scans)
	m.mockDb.EXPECT().GetSettingByName(gomock.Any(), gomock.Any()).Times(1).Return(dbsql.GetSettingByNameRow{Settingdata: settings.DefaultSettingsYAML, Datatype: "internal"}, nil)
	m.mockDb.EXPECT().UpdateScanState(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	return server.GetScanErrors(c)
}

type SettingsMockHandler struct {
	mockDb *db.MockQuerier
}

func NewSettingsMockHandler(mockParam *db.MockQuerier) SettingsMockHandler {
	handler := SettingsMockHandler{mockParam}
	return handler
}
func (m *SettingsMockHandler) GetSettings(ctx echo.Context) error {
	var r = []dbsql.Setting{dbsql.Setting{Name: "test1"}}
	response := make([]GetSettingsResponse, 0, 1)
	response = append(response, GetSettingsResponse{Name: "test1", Contents: settings.DefaultSettingsYAML})
	m.mockDb.EXPECT().GetSettings(gomock.Any()).Times(1).Return(r, nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.GetSettings(ctx)
}

func (m *SettingsMockHandler) SetSetting(c echo.Context) error {
	m.mockDb.EXPECT().SetSettings(gomock.Any(), gomock.Any()).
		Times(1).
		Return(nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.SetSetting(c)
}

func (m *SettingsMockHandler) UpdateSettingByName(c echo.Context) error {
	m.mockDb.EXPECT().UpdateSettings(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	m.mockDb.EXPECT().GetSettingByName(gomock.Any(), gomock.Any()).Times(1).Return(dbsql.GetSettingByNameRow{Settingdata: `{"test":"test"}`, Datatype: "test"}, nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.UpdateSettingByName(c)
}
func (m *SettingsMockHandler) GetSetting(c echo.Context) error {
	m.mockDb.EXPECT().GetSettingByName(gomock.Any(), gomock.Any()).Times(1).Return(dbsql.GetSettingByNameRow{Settingdata: `{"test":"test"}`, Datatype: "test"}, nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.GetSettingByName(c)
}

type TargetsMockHandler struct {
	mockDb *db.MockQuerier
}

func NewTargetsMockHandler(mockParam *db.MockQuerier) TargetsMockHandler {
	handler := TargetsMockHandler{mockParam}
	return handler
}
func (m *TargetsMockHandler) GetTargets(ctx echo.Context) error {
	tempdir, _ := ioutil.TempDir("", "test-dir-*")
	defer os.RemoveAll(tempdir)
	var r = []dbsql.GetTargetsRow{dbsql.GetTargetsRow{ID: 1, Name: "test1"}}
	m.mockDb.EXPECT().GetTargets(gomock.Any()).Times(1).Return(r, nil)
	target := targets.NewTargetsStorage(tempdir)
	server := handlers.New(m.mockDb, target, nil)
	return server.GetTargets(ctx)
}

func (m *TargetsMockHandler) AddTarget(ctx echo.Context) error {
	tempdir, _ := ioutil.TempDir("", "test-dir-*")
	defer os.RemoveAll(tempdir)
	m.mockDb.EXPECT().AddTarget(gomock.Any(), gomock.Any()).
		Times(1).
		Return(int64(1), nil)
	target := targets.NewTargetsStorage(tempdir)
	server := handlers.New(m.mockDb, target, nil)
	return server.AddTarget(ctx)
}

func (m *TargetsMockHandler) UpdateTarget(ctx echo.Context) error {
	tempdir, _ := ioutil.TempDir("", "test-dir-*")
	defer os.RemoveAll(tempdir)
	m.mockDb.EXPECT().UpdateTargetMetadata(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	target := targets.NewTargetsStorage(tempdir)
	server := handlers.New(m.mockDb, target, nil)
	return server.UpdateTarget(ctx)
}

func (m *TargetsMockHandler) DeleteTarget(c echo.Context) error {
	tempdir, _ := ioutil.TempDir("", "test-dir-*")
	ioutil.WriteFile(filepath.Join(tempdir, "1"), []byte("example.com"), os.ModePerm)
	defer os.RemoveAll(tempdir)
	m.mockDb.EXPECT().DeleteTarget(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	m.mockDb.EXPECT().GetTarget(gomock.Any(), gomock.Any()).Times(1).Return(dbsql.GetTargetRow{
		Internalid: "1", Name: "test"}, nil)
	target := targets.NewTargetsStorage(tempdir)
	server := handlers.New(m.mockDb, target, nil)
	return server.DeleteTarget(c)
}

func (m *TargetsMockHandler) GetTargetContents(c echo.Context) error {
	tempdir, _ := ioutil.TempDir("", "test-dir-*")
	ioutil.WriteFile(filepath.Join(tempdir, "1"), []byte("example.com"), os.ModePerm)
	defer os.RemoveAll(tempdir)
	m.mockDb.EXPECT().GetTarget(gomock.Any(), gomock.Any()).Times(1).Return(dbsql.GetTargetRow{
		Internalid: "1", Name: "test"}, nil)
	target := targets.NewTargetsStorage(tempdir)
	server := handlers.New(m.mockDb, target, nil)
	return server.GetTargetContents(c)
}

type TemplateMockHandler struct {
	mockDb *db.MockQuerier
}

func NewTemplateMockHandler(mockParam *db.MockQuerier) TemplateMockHandler {
	handler := TemplateMockHandler{mockParam}
	return handler
}

func (m *TemplateMockHandler) GetTemplates(ctx echo.Context) error {
	server := handlers.New(m.mockDb, nil, nil)
	m.mockDb.EXPECT().GetTemplatesByFolder(gomock.Any(), gomock.Any()).Times(1).Return(
		[]dbsql.GetTemplatesByFolderRow{{ID: 1, Name: "test"}}, nil)
	return server.GetTemplates(ctx)
}

func (m *TemplateMockHandler) AddTemplate(ctx echo.Context) error {
	m.mockDb.EXPECT().AddTemplate(gomock.Any(), gomock.Any()).
		Times(1).
		Return(int64(1), nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.AddTemplate(ctx)
}

func (m *TemplateMockHandler) UpdateTemplate(ctx echo.Context) error {
	m.mockDb.EXPECT().UpdateTemplate(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.UpdateTemplate(ctx)
}

func (m *TemplateMockHandler) DeleteTemplate(c echo.Context) error {
	m.mockDb.EXPECT().DeleteTemplate(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.DeleteTemplate(c)
}

func (m *TemplateMockHandler) GetTemplatesRaw(c echo.Context) error {
	m.mockDb.EXPECT().
		GetTemplateContents(gomock.Any(), gomock.Eq("test.yaml")).
		Times(1).
		Return("test-contents", nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.GetTemplatesRaw(c)
}

func (m *TemplateMockHandler) ExecuteTemplate(c echo.Context) error {
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
	m.mockDb.EXPECT().
		GetTemplateContents(gomock.Any(), gomock.Any()).
		Times(1).
		Return(testTemplate, nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.ExecuteTemplate(c)
}
