package client

import (
	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/handlers"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
)

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
