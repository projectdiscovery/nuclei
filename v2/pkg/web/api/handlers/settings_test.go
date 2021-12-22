package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo/v4"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
	"github.com/stretchr/testify/require"
)

func TestSetSettingsHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var buf bytes.Buffer
	settings := SetSettingRequest{
		Name:     "test",
		Contents: "test",
		Type:     "internal",
	}
	_ = jsoniter.NewEncoder(&buf).Encode(&settings)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", &buf)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSONCharsetUTF8)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	querier := db.NewMockQuerier(ctrl)
	querier.EXPECT().
		SetSettings(gomock.Any(), gomock.Any()).
		Times(1).
		Return(nil)

	server := New(querier, nil, nil)

	err := server.SetSetting(c)
	require.NoError(t, err, "could not set setting")
	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")
}

func TestUpdateSettingsHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var buf bytes.Buffer
	settings := SetSettingRequest{
		Name:     "test",
		Contents: "test",
		Type:     "internal",
	}
	_ = jsoniter.NewEncoder(&buf).Encode(&settings)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", &buf)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSONCharsetUTF8)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	querier := db.NewMockQuerier(ctrl)
	querier.EXPECT().
		SetSettings(gomock.Any(), gomock.Any()).
		Times(1).
		Return(nil)

	server := New(querier, nil, nil)

	err := server.SetSetting(c)
	require.NoError(t, err, "could not set setting")
	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")

	buf.Reset()

	update := UpdateSettingRequest{
		Contents: "update",
		Type:     "internal",
	}
	_ = jsoniter.NewEncoder(&buf).Encode(&update)

	e = echo.New()
	req = httptest.NewRequest(http.MethodPut, "/", &buf)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSONCharsetUTF8)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)

	c.SetPath("/:name")
	c.SetParamNames("name")
	c.SetParamValues("test")

	querier = db.NewMockQuerier(ctrl)
	querier.EXPECT().
		UpdateSettings(gomock.Any(), gomock.Eq(dbsql.UpdateSettingsParams{
			Settingdata: "update",
			Name:        "test",
		})).
		Times(1).
		Return(nil)

	server = New(querier, nil, nil)

	err = server.UpdateSettingByName(c)
	require.NoError(t, err, "could not set setting")
	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")
}
