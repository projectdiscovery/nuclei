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
	"github.com/stretchr/testify/require"
)

func TestAddTemplateHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jsonBody := AddTemplateRequest{
		Contents: "test-contents",
		Path:     "template.yaml",
	}
	var buf bytes.Buffer
	_ = jsoniter.NewEncoder(&buf).Encode(&jsonBody)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", &buf)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	querier := db.NewMockQuerier(ctrl)
	querier.EXPECT().
		AddTemplate(gomock.Any(), gomock.Any()).
		Times(1).
		Return(int64(1), nil)

	server := New(querier, nil, nil)

	err := server.AddTemplate(c)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, rec.Result().StatusCode, "could not get correct status code")
}
