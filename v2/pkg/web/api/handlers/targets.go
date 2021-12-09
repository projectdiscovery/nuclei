package handlers

import (
	"context"
	"database/sql"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo/v4"
	"gopkg.in/yaml.v2"
)

// GetTargetsResponse is a response for /targets listing
type GetTargetsResponse struct {
	ID        int64                        `json:"id"`
	Name      string                       `json:"name"`
	Folder    bool                         `json:"folder"`
	Filepaths []GetTargetsResponseFilepath `json:"paths"`
	Createdat time.Time                    `json:"createdAt"`
	Updatedat time.Time                    `json:"updatedAt"`
}

// GetTargetsResponseFilepath is a path structure for get targets response
type GetTargetsResponseFilepath struct {
	ID       string `json:"id"`
	Filename string `json:"filename"`
	Total    string `json:"total"`
}

// GetTargets handlers /targets listing route
func (s *Server) GetTargets(ctx echo.Context) error {
	if search := ctx.QueryParam("search"); search != "" {
		return s.getTargetsWithSearchKey(ctx, search)
	}
	return s.getTargets(ctx)
}

// getTargets returns targets list
func (s *Server) getTargets(ctx echo.Context) error {
	targets, err := s.db.Queries().GetTargets(context.Background())
	if err != nil {
		return err
	}
	targetsList := make([]GetTargetsResponse, 0, len(targets))
	for _, target := range targets {
		var filepaths []GetTargetsResponseFilepath
		if err := jsoniter.Unmarshal(target.Filepaths.Bytes, &filepaths); err != nil {
			_ = err
		}

		targetsList = append(targetsList, GetTargetsResponse{
			ID:        target.ID,
			Name:      target.Name.String,
			Folder:    target.Folder.Bool,
			Createdat: target.Createdat.Time,
			Updatedat: target.Updatedat.Time,
			Filepaths: filepaths,
		})
	}
	return ctx.JSON(200, targetsList)
}

// getTargetsWithSearchKey returns targets for a search key
func (s *Server) getTargetsWithSearchKey(ctx echo.Context, searchKey string) error {
	targets, err := s.db.Queries().GetTargetsForSearch(context.Background(), sql.NullString{String: searchKey, Valid: true})
	if err != nil {
		return err
	}
	targetsList := make([]GetTargetsResponse, 0, len(targets))
	for _, target := range targets {
		var filepaths []GetTargetsResponseFilepath
		if err := jsoniter.Unmarshal(target.Filepaths.Bytes, &filepaths); err != nil {
			_ = err
		}

		targetsList = append(targetsList, GetTargetsResponse{
			ID:        target.ID,
			Name:      target.Name.String,
			Folder:    target.Folder.Bool,
			Createdat: target.Createdat.Time,
			Updatedat: target.Updatedat.Time,
			Filepaths: filepaths,
		})
	}
	return ctx.JSON(200, targetsList)
}

// AddTargetRequest is a request for /targets addition
type AddTargetRequest struct {
	Contents string `json:"contents"`
	Path     string `json:"path"`
	Name     string `json:"name"`
	Folder   bool   `json:"folder"`
}

// AddTarget handles /targets addition route
func (s *Server) AddTarget(ctx echo.Context) error {
	var body AddTargetRequest
	if err := jsoniter.NewDecoder(ctx.Request().Body).Decode(&body); err != nil {
		return err
	}

	var templateNameInfo templateNameInfoStructure
	if err := yaml.NewDecoder(strings.NewReader(body.Contents)).Decode(&templateNameInfo); err != nil {
		return err
	}
	//err := s.db.Queries().AddTarget(context.Background(), dbsql.AddTargetParams{
	//	Name:   sql.NullString{String: body.Name, Valid: true},
	//	Folder: sql.NullBool{Bool: body.Folder, Valid: true},
	//	Filepaths: pgtype.JSON{Bytes: },
	//})
	return nil
}
