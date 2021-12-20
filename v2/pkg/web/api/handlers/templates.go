package handlers

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
)

// GetTemplatesResponse is a response for /templates listing
type GetTemplatesResponse struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Folder    string    `json:"folder"`
	Path      string    `json:"path"`
	Createdat time.Time `json:"createdAt"`
	Updatedat time.Time `json:"updatedAt"`
}

// GetTemplates handlers /templates listing route
func (s *Server) GetTemplates(ctx echo.Context) error {
	if folder := ctx.QueryParam("folder"); folder != "" {
		return s.getTemplatesWithFolder(ctx, folder)
	}
	if search := ctx.QueryParam("search"); search != "" {
		return s.getTemplatesWithSearchKey(ctx, search)
	}
	return s.getTemplates(ctx)
}

// getTemplates handles getting templates
func (s *Server) getTemplates(ctx echo.Context) error {
	rows, err := s.db.GetTemplates(context.Background())
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get templates from db").Error())
	}
	response := make([]GetTemplatesResponse, 0, len(rows))
	for _, row := range rows {
		response = append(response, GetTemplatesResponse{
			ID:        row.ID,
			Name:      row.Name,
			Folder:    row.Folder,
			Path:      row.Path,
			Createdat: row.Createdat,
			Updatedat: row.Updatedat,
		})
	}
	return ctx.JSON(200, response)
}

// getTemplatesWithFolder handles getting templates by a folder
func (s *Server) getTemplatesWithFolder(ctx echo.Context, folder string) error {
	rows, err := s.db.GetTemplatesByFolder(context.Background(), folder)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get templates from db").Error())
	}
	response := make([]GetTemplatesResponse, 0, len(rows))
	for _, row := range rows {
		response = append(response, GetTemplatesResponse{
			ID:        row.ID,
			Name:      row.Name,
			Folder:    folder,
			Path:      row.Path,
			Createdat: row.Createdat,
			Updatedat: row.Updatedat,
		})
	}
	return ctx.JSON(200, response)
}

// getTemplatesWithSearchKey handles getting templates by a search key for path
func (s *Server) getTemplatesWithSearchKey(ctx echo.Context, searchKey string) error {
	rows, err := s.db.GetTemplatesBySearchKey(context.Background(), sql.NullString{String: searchKey, Valid: true})
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get templates from db").Error())
	}
	response := make([]GetTemplatesResponse, 0, len(rows))
	for _, row := range rows {
		response = append(response, GetTemplatesResponse{
			ID:        row.ID,
			Name:      row.Name,
			Folder:    row.Folder,
			Path:      row.Path,
			Createdat: row.Createdat,
			Updatedat: row.Updatedat,
		})
	}
	return ctx.JSON(200, response)
}

// UpdateTemplateRequest is a request for /templates update
type UpdateTemplateRequest struct {
	Contents string `json:"contents"`
	Path     string `json:"path"`
}

// UpdateTemplate handles /templates updating route
func (s *Server) UpdateTemplate(ctx echo.Context) error {
	var body UpdateTemplateRequest
	if err := jsoniter.NewDecoder(ctx.Request().Body).Decode(&body); err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not unmarshal body").Error())
	}
	err := s.db.UpdateTemplate(context.Background(), dbsql.UpdateTemplateParams{
		Contents:  body.Contents,
		Updatedat: time.Now(),
		Path:      body.Path,
	})
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not update template to db").Error())
	}
	return nil
}

// AddTemplateRequest is a request for /templates addition
type AddTemplateRequest struct {
	Contents string `json:"contents"`
	Path     string `json:"path"`
	Folder   string `json:"folder"`
}

// AddTemplate handles /templates addition route
func (s *Server) AddTemplate(ctx echo.Context) error {
	var body AddTemplateRequest
	if err := jsoniter.NewDecoder(ctx.Request().Body).Decode(&body); err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not unmarshal body").Error())
	}
	id, err := s.db.AddTemplate(context.Background(), dbsql.AddTemplateParams{
		Contents: body.Contents,
		Folder:   body.Folder,
		Path:     body.Path,
		Name:     filepath.Base(body.Path),
	})
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not add template to db").Error())
	}
	return ctx.JSON(200, map[string]int64{"id": id})
}

// DeleteTemplateRequest is a request for /templates deletion
type DeleteTemplateRequest struct {
	Path string `json:"path"`
}

// DeleteTemplate handles /templates deletion route
func (s *Server) DeleteTemplate(ctx echo.Context) error {
	var body DeleteTemplateRequest
	if err := jsoniter.NewDecoder(ctx.Request().Body).Decode(&body); err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not unmarshal body").Error())
	}
	err := s.db.DeleteTemplate(context.Background(), body.Path)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not delete template to db").Error())
	}
	return err
}

// GetTemplatesRaw handlers /templates content retrieval route
func (s *Server) GetTemplatesRaw(ctx echo.Context) error {
	templatePath := ctx.QueryParam("path")
	if templatePath == "" {
		return echo.NewHTTPError(500, "no path specified for template")
	}
	contents, err := s.db.GetTemplateContents(context.Background(), templatePath)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get template from db").Error())
	}
	return ctx.String(200, contents)
}

// ExecuteTemplateRequest is a request for /templates execution
type ExecuteTemplateRequest struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}

// ExecuteTemplateResponse is a response for /templates execution
type ExecuteTemplateResponse struct {
	Output []*output.ResultEvent `json:"output,omitempty"`
	Debug  map[string]string     `json:"debug"` // Contains debug request response kv pairs
}

// ExecuteTemplate handles /templates execution route
func (s *Server) ExecuteTemplate(ctx echo.Context) error {
	var body ExecuteTemplateRequest
	if err := jsoniter.NewDecoder(ctx.Request().Body).Decode(&body); err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not unmarshal body").Error())
	}
	templateContents, err := s.db.GetTemplateContents(context.Background(), body.Path)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get template").Error())
	}
	template, err := templates.Parse(strings.NewReader(templateContents), "", nil, *testutils.NewMockExecuterOptions(testutils.DefaultOptions, &testutils.TemplateInfo{}))
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not parse template").Error())
	}
	var results []*output.ResultEvent
	debugData := make(map[string]string)

	err = template.Executer.ExecuteWithResults(body.Target, func(event *output.InternalWrappedEvent) {
		results = append(results, event.Results...)
		if event.Debug != nil {
			debugData[event.Debug.Request] = event.Debug.Response
		}
	})
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not execute template").Error())
	}
	resp := &ExecuteTemplateResponse{Debug: debugData, Output: results}
	return ctx.JSON(200, resp)
}
