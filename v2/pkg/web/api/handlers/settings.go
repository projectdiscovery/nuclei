package handlers

import (
	"context"

	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
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
	settings, err := s.db.GetSettings(context.Background())
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get settings from db").Error())
	}
	response := make([]GetSettingsResponse, len(settings))
	for i, setting := range settings {
		response[i] = GetSettingsResponse{
			Name:     setting.Name,
			Type:     setting.Datatype,
			Contents: setting.Settingdata,
		}
	}
	return ctx.JSON(200, response)
}

// GetSettingByName handlers /setting/:name listing route
func (s *Server) GetSettingByName(ctx echo.Context) error {
	name := ctx.Param("name")

	settings, err := s.db.GetSettingByName(context.Background(), name)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get setting from db").Error())
	}
	response := GetSettingsResponse{
		Name:     name,
		Type:     settings.Datatype,
		Contents: settings.Settingdata,
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
		return echo.NewHTTPError(400, errors.Wrap(err, "could not unmarshal body").Error())
	}
	err := s.db.SetSettings(context.Background(), dbsql.SetSettingsParams{
		Settingdata: body.Contents,
		Datatype:    body.Type,
		Name:        body.Name,
	})
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not set settings to db").Error())
	}
	return nil
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
		return echo.NewHTTPError(400, errors.Wrap(err, "could not unmarshal body").Error())
	}
	err := s.db.UpdateSettings(context.Background(), dbsql.UpdateSettingsParams{
		Settingdata: body.Contents,
		Name:        name,
	})
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not update settings to db").Error())
	}
	return nil
}
