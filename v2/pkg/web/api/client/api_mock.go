package client

import (
	"context"
	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
	"testing"
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
	apiGroup.GET("/settings/:name", handler.settings.GetSettingByName)
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
