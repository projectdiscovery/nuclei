package client

import (
	"context"
	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/handlers"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/targets"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
	"io/ioutil"
	"os"
	"testing"
)

type MockApiHandler struct {
	mockDb *db.MockQuerier
	ctrl   *gomock.Controller
}

func NewMockApiHandler(t *testing.T) MockApiHandler {
	//_ = protocolinit.Init(types.DefaultOptions())
	handler := MockApiHandler{}
	handler.ctrl = gomock.NewController(t)
	handler.mockDb = db.NewMockQuerier(handler.ctrl)
	return handler
}
func (m *MockApiHandler) Finish() {
	m.ctrl.Finish()
}

func (m *MockApiHandler) GetTemplates(ctx echo.Context) error {
	response := []GetTemplatesResponse{}
	response = append(response, GetTemplatesResponse{ID: 1, Name: "test1"})
	server := handlers.New(m.mockDb, nil, nil)
	m.mockDb.EXPECT().GetTemplates(gomock.Any()).Times(1).Return(response, nil)
	m.mockDb.EXPECT().GetTemplatesByFolderOne(gomock.Any(), gomock.Any()).Times(1).Return(response, nil)
	m.mockDb.EXPECT().GetTemplatesBySearchKey(gomock.Any(), gomock.Any()).Times(1).Return(response, nil)
	return server.GetTemplates(ctx)
}

func (m *MockApiHandler) AddTemplate(ctx echo.Context) error {
	m.mockDb.EXPECT().AddTemplate(gomock.Any(), gomock.Any()).
		Times(1).
		Return(int64(1), nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.AddTemplate(ctx)
}

func (m *MockApiHandler) UpdateTemplate(ctx echo.Context) error {
	m.mockDb.EXPECT().UpdateTemplate(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.UpdateTemplate(ctx)
}

func (m *MockApiHandler) DeleteTemplate(c echo.Context) error {
	m.mockDb.EXPECT().DeleteTemplate(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.DeleteTemplate(c)
}

func (m *MockApiHandler) GetTemplatesRaw(c echo.Context) error {
	m.mockDb.EXPECT().
		GetTemplateContents(gomock.Any(), gomock.Eq("test.yaml")).
		Times(1).
		Return("test-contents", nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.GetTemplatesRaw(c)
}

func (m *MockApiHandler) ExecuteTemplate(c echo.Context) error {
	m.mockDb.EXPECT().
		GetTemplateContents(gomock.Any(), gomock.Any()).
		Times(1).
		Return("test-contents", nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.ExecuteTemplate(c)
}

func (m *MockApiHandler) GetTargets(ctx echo.Context) error {
	tempdir, _ := ioutil.TempDir("", "test-dir-*")
	defer os.RemoveAll(tempdir)
	var r = []dbsql.GetTargetsRow{dbsql.GetTargetsRow{ID: 1, Name: "test1"}}
	m.mockDb.EXPECT().GetTargets(gomock.Any()).Times(1).Return(r, nil)
	target := targets.NewTargetsStorage(tempdir)
	server := handlers.New(m.mockDb, target, nil)
	return server.GetTargets(ctx)
}

func (m *MockApiHandler) AddTarget(ctx echo.Context) error {
	tempdir, _ := ioutil.TempDir("", "test-dir-*")
	defer os.RemoveAll(tempdir)
	m.mockDb.EXPECT().AddTarget(gomock.Any(), gomock.Any()).
		Times(1).
		Return(int64(1), nil)
	target := targets.NewTargetsStorage(tempdir)
	server := handlers.New(m.mockDb, target, nil)
	return server.AddTarget(ctx)
}

func (m *MockApiHandler) UpdateTarget(ctx echo.Context) error {
	tempdir, _ := ioutil.TempDir("", "test-dir-*")
	defer os.RemoveAll(tempdir)
	m.mockDb.EXPECT().UpdateTargetMetadata(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	target := targets.NewTargetsStorage(tempdir)
	server := handlers.New(m.mockDb, target, nil)
	return server.UpdateTarget(ctx)
}

func (m *MockApiHandler) DeleteTarget(c echo.Context) error {
	tempdir, _ := ioutil.TempDir("", "test-dir-*")
	defer os.RemoveAll(tempdir)
	m.mockDb.EXPECT().DeleteTarget(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	target := targets.NewTargetsStorage(tempdir)
	server := handlers.New(m.mockDb, target, nil)
	return server.DeleteTarget(c)
}

//func (m *MockApiHandler) GetTargetContents(c echo.Context) error {
//	response := make([]GetTargetsResponse, 0, 1)
//	response = append(response, GetTargetsResponse{ID: 1, Name: "test1"})
//	m.mockDb.EXPECT().gettar
//	server := handlers.New(m.mockDb, nil, nil)
//	return server.GetTargetContents(c)
//}

func (m *MockApiHandler) GetSettings(ctx echo.Context) error {
	var r = []dbsql.Setting{dbsql.Setting{Name: "test1"}}
	response := make([]GetSettingsResponse, 0, 1)
	response = append(response, GetSettingsResponse{Name: "test1"})
	m.mockDb.EXPECT().GetSettings(gomock.Any()).Times(1).Return(r, nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.GetSettings(ctx)
}

func (m *MockApiHandler) SetSetting(c echo.Context) error {
	m.mockDb.EXPECT().SetSettings(gomock.Any(), gomock.Any()).
		Times(1).
		Return(nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.SetSetting(c)
}

func (m *MockApiHandler) UpdateSettingByName(c echo.Context) error {
	m.mockDb.EXPECT().UpdateSettings(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.UpdateSettingByName(c)
}

func (m *MockApiHandler) GetScans(c echo.Context) error {
	var r = []dbsql.Scan{dbsql.Scan{ID: 1, Name: "test1"}}
	m.mockDb.EXPECT().GetScans(gomock.Any()).Times(1).Return(r, nil)
	m.mockDb.EXPECT().GetScansBySearchKey(gomock.Any(), gomock.Any()).Times(1).Return(r, nil)
	//m.mockDb.EXPECT().GetScansForSchedule(gomock.Any(), gomock.Any()).Times(1).Return(r, nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.GetScans(c)
}

func (m *MockApiHandler) AddScan(c echo.Context) error {
	m.mockDb.EXPECT().AddScan(gomock.Any(), gomock.Any()).
		Times(1).
		Return(int64(1), nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.AddScan(c)
}

//func (m *MockApiHandler) GetScanProgress(c echo.Context) error {
//	//m.mockDb.EXPECT().getsca(gomock.Any(), gomock.Any()).Times(1).Return(nil)
//	//server := handlers.New(m.mockDb, nil, nil)
//	return server.UpdateTemplate(c)
//}

func (m *MockApiHandler) GetScan(c echo.Context) error {
	m.mockDb.EXPECT().GetScan(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.GetScan(c)
}

func (m *MockApiHandler) UpdateScan(c echo.Context) error {
	m.mockDb.EXPECT().UpdateScanState(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.UpdateScan(c)
}

func (m *MockApiHandler) DeleteScan(c echo.Context) error {
	m.mockDb.EXPECT().DeleteScan(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.DeleteScan(c)
}

//func (m *MockApiHandler) ExecuteScan(c echo.Context) error {
//	m.mockDb.EXPECT().ExecuteScan(gomock.Any(), gomock.Any()).Times(1).Return(nil)
//	server := handlers.New(m.mockDb, nil, nil)
//	return server.ExecuteScan(c)
//
//}

//func (m *MockApiHandler) GetScanMatches(c echo.Context) error {
//	m.mockDb.EXPECT().GetScanMatches(gomock.Any(), gomock.Any()).Times(1).Return(nil)
//	server := handlers.New(m.mockDb, nil, nil)
//	return server.GetScanMatches(c)
//
//}

//func (m *MockApiHandler) GetScanErrors(c echo.Context) error {
//	m.mockDb.EXPECT().GetScanErrors(gomock.Any(), gomock.Any()).Times(1).Return(nil)
//	server := handlers.New(m.mockDb, nil, nil)
//	return server.GetScanErrors(c)
//
//}

func (m *MockApiHandler) GetIssues(c echo.Context) error {
	response := make([]GetIssuesResponse, 0, 1)
	response = append(response, GetIssuesResponse{ID: 1})
	m.mockDb.EXPECT().GetIssues(gomock.Any()).Times(1).Return(response)
	server := handlers.New(m.mockDb, nil, nil)
	return server.GetIssues(c)
}

func (m *MockApiHandler) AddIssue(c echo.Context) error {
	m.mockDb.EXPECT().AddIssue(gomock.Any(), gomock.Any()).
		Times(1).
		Return(int64(1), nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.AddIssue(c)
}

//func (m *MockApiHandler) GetIssue(c echo.Context) error {
//	response := make([]getiss)
//	m.mockDb.EXPECT().GetIssue(gomock.Any(), gomock.Any()).Times(1).Return(response)
//	server := handlers.New(m.mockDb, nil, nil)
//	return server.GetIssues(c)
//
//}

func (m *MockApiHandler) UpdateIssue(c echo.Context) error {
	m.mockDb.EXPECT().UpdateIssue(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.UpdateIssue(c)
}

func (m *MockApiHandler) DeleteIssue(c echo.Context) error {
	m.mockDb.EXPECT().DeleteIssue(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	server := handlers.New(m.mockDb, nil, nil)
	return server.DeleteIssue(c)
}

//func (m *MockApiHandler) GetSettingByName(c echo.Context) error {
//
//}

func NewMockHttpServer(t *testing.T) func() {
	ctx := context.Background()
	handler := NewMockApiHandler(t)
	e := echo.New()
	e.HideBanner = true
	apiGroup := e.Group("/api/v1")
	apiGroup.GET("/templates", handler.GetTemplates)
	apiGroup.POST("/templates", handler.AddTemplate)
	apiGroup.PUT("/templates", handler.UpdateTemplate)
	apiGroup.DELETE("/templates", handler.DeleteTemplate)
	apiGroup.GET("/templates/raw", handler.GetTemplatesRaw)
	apiGroup.POST("/templates/execute", handler.ExecuteTemplate)
	//targets
	apiGroup.GET("/targets", handler.GetTargets)
	apiGroup.POST("/targets", handler.AddTarget)
	apiGroup.PUT("/targets/:id", handler.UpdateTarget)
	apiGroup.DELETE("/targets/:id", handler.DeleteTarget)
	//apiGroup.GET("/targets/:id", handler.GetTargetContents)
	//settings
	apiGroup.GET("/settings", handler.GetSettings)
	apiGroup.POST("/settings", handler.SetSetting)
	//apiGroup.GET("/settings/:name", handler.GetSettingByName)
	apiGroup.PUT("/settings/:name", handler.UpdateSettingByName)
	//scans
	apiGroup.GET("/scans", handler.GetScans)
	apiGroup.POST("/scans", handler.AddScan)
	//apiGroup.GET("/scans/progress", handler.GetScanProgress)
	apiGroup.GET("/scans/:id", handler.GetScan)
	apiGroup.PUT("/scans/:id", handler.UpdateScan)
	apiGroup.DELETE("/scans/:id", handler.DeleteScan)
	//apiGroup.GET("/scans/:id/execute", handler.ExecuteScan)
	//apiGroup.GET("/scans/:id/matches", handler.GetScanMatches)
	//apiGroup.GET("/scans/:id/errors", handler.GetScanErrors)
	//issues
	apiGroup.GET("/issues", handler.GetIssues)
	apiGroup.POST("/issues", handler.AddIssue)
	//apiGroup.GET("/issues/:id", handler.GetIssue)
	apiGroup.PUT("/issues/:id", handler.UpdateIssue)
	apiGroup.DELETE("/issues/:id", handler.DeleteIssue)

	go e.Start(":8822")
	return func() {
		handler.Finish()
		e.Shutdown(ctx)
	}
}
