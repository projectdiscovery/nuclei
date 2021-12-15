package handlers

import (
	"context"
	"database/sql"

	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo/v4"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
)

// GetSettingsResponse is a response for /settings listing
type GetSettingsResponse struct {
	Name     string `json:"name"`
	Contents string `json:"contents"`
	Type     string `json:"type"`
}

type SettingType string

const (
	SettingTypeInternal  SettingType = "internal"
	SettingTypeReporting SettingType = "reporting"
)

// GetSettings handlers /settings listing route
func (s *Server) GetSettings(ctx echo.Context) error {
	settings, err := s.db.Queries().GetSettings(context.Background())
	if err != nil {
		return err
	}
	response := make([]GetSettingsResponse, len(settings))
	for i, setting := range settings {
		response[i] = GetSettingsResponse{
			Name:     setting.Name.String,
			Type:     setting.Datatype.String,
			Contents: setting.Settingdata.String,
		}
	}
	return ctx.JSON(200, response)
}

// GetSettingByName handlers /setting/:name listing route
func (s *Server) GetSettingByName(ctx echo.Context) error {
	name := ctx.Param("name")

	settings, err := s.db.Queries().GetSettingByName(context.Background(), sql.NullString{String: name, Valid: true})
	if err != nil {
		return err
	}
	response := GetSettingsResponse{
		Name:     name,
		Type:     settings.Datatype.String,
		Contents: settings.Settingdata.String,
	}
	return ctx.JSON(200, response)
}

// SetSettingRequest is a request for /settings addition
type SetSettingRequest struct {
	Name     string `json:"name"`
	Contents string `json:"contents"`
	Type     string `json:"type"`
}

// SetSetting handlers /settings setting route
func (s *Server) SetSetting(ctx echo.Context) error {
	var body SetSettingRequest
	if err := jsoniter.NewDecoder(ctx.Request().Body).Decode(&body); err != nil {
		return err
	}
	err := s.db.Queries().SetSettings(context.Background(), dbsql.SetSettingsParams{
		Settingdata: sql.NullString{String: body.Contents, Valid: true},
		Datatype:    sql.NullString{String: body.Type, Valid: true},
		Name:        sql.NullString{String: body.Name, Valid: true},
	})
	return err
}

// UpdateSettingRequest is a request for /settings updation
type UpdateSettingRequest struct {
	Contents string `json:"contents"`
	Type     string `json:"type"`
}

// UpdateSettingByName handlers /settings update route
func (s *Server) UpdateSettingByName(ctx echo.Context) error {
	name := ctx.Param("name")

	var body UpdateSettingRequest
	if err := jsoniter.NewDecoder(ctx.Request().Body).Decode(&body); err != nil {
		return err
	}
	err := s.db.Queries().UpdateSettings(context.Background(), dbsql.UpdateSettingsParams{
		Settingdata: sql.NullString{String: body.Contents, Valid: true},
		Name:        sql.NullString{String: name, Valid: true},
	})
	return err
}
