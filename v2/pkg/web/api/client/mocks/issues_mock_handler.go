package mocks

import (
	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/handlers"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
)

type IssuesMockHandler struct {
	mockDb *db.MockQuerier
}

func NewIssuesMockHandler(mockParam *db.MockQuerier) IssuesMockHandler {
	handler := IssuesMockHandler{mockParam}
	return handler
}
func (m *IssuesMockHandler) GetIssues(c echo.Context) error {
	var r = []dbsql.GetIssuesRow{{ID: 1}}
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
