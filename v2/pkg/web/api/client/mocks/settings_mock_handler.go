package mocks

import (
	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/handlers"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
)

type SettingsMockHandler struct {
	mockDb *db.MockQuerier
}

func NewSettingsMockHandler(mockParam *db.MockQuerier) SettingsMockHandler {
	handler := SettingsMockHandler{mockParam}
	return handler
}
func (m *SettingsMockHandler) GetSettings(ctx echo.Context) error {
	var r = []dbsql.Setting{{Name: "test1"}}
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
