package client

import (
	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/handlers"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/targets"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
	"io/ioutil"
	"os"
	"path/filepath"
)

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
