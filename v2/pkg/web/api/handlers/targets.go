package handlers

import (
	"context"
	"database/sql"
	"io"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/targets"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
)

// GetTargetsResponse is a response for /targets listing
type GetTargetsResponse struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	InternalID string    `json:"internalId"`
	Filename   string    `json:"filename"`
	Total      int64     `json:"total"`
	Createdat  time.Time `json:"createdAt"`
	Updatedat  time.Time `json:"updatedAt"`
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
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get targets from db"))
	}
	targetsList := make([]GetTargetsResponse, 0, len(targets))
	for _, target := range targets {
		targetsList = append(targetsList, GetTargetsResponse{
			ID:         target.ID,
			Name:       target.Name.String,
			Createdat:  target.Createdat.Time,
			Updatedat:  target.Updatedat.Time,
			Filename:   target.Filename.String,
			InternalID: target.Internalid.String,
			Total:      target.Total.Int64,
		})
	}
	return ctx.JSON(200, targetsList)
}

// getTargetsWithSearchKey returns targets for a search key
func (s *Server) getTargetsWithSearchKey(ctx echo.Context, searchKey string) error {
	targets, err := s.db.Queries().GetTargetsForSearch(context.Background(), sql.NullString{String: searchKey, Valid: true})
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get targets from db"))
	}
	targetsList := make([]GetTargetsResponse, 0, len(targets))
	for _, target := range targets {
		targetsList = append(targetsList, GetTargetsResponse{
			ID:         target.ID,
			Name:       target.Name.String,
			Createdat:  target.Createdat.Time,
			Updatedat:  target.Updatedat.Time,
			Filename:   target.Filename.String,
			InternalID: target.Internalid.String,
			Total:      target.Total.Int64,
		})
	}
	return ctx.JSON(200, targetsList)
}

// AddTarget handles /targets addition route
// It accepts multipart-form format.
func (s *Server) AddTarget(ctx echo.Context) error {
	targetPath := ctx.FormValue("path")
	targetName := ctx.FormValue("name")

	targetContents, err := ctx.FormFile("contents")
	if err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not parse file contents"))
	}
	file, err := targetContents.Open()
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not open file contents"))
	}
	defer file.Close()

	writer, id, err := s.targets.Create()
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not create target file"))
	}
	defer writer.Close()

	newlineCounter := &targets.NewLineCountWriter{}

	// Merge two writers to write to file as well as count newlines
	finalWriter := io.MultiWriter(writer, newlineCounter)
	_, err = io.Copy(finalWriter, file)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not write to target file"))
	}

	gotID, err := s.db.Queries().AddTarget(context.Background(), dbsql.AddTargetParams{
		Name:       sql.NullString{String: targetName, Valid: true},
		Internalid: sql.NullString{String: id, Valid: true},
		Filename:   sql.NullString{String: targetPath, Valid: true},
		Total:      sql.NullInt64{Int64: newlineCounter.Total, Valid: true},
	})
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not add target to db"))
	}
	return ctx.JSON(200, map[string]int64{"id": gotID})
}

// UpdateTarget handles /targets update route
// It accepts multipart-form format.
func (s *Server) UpdateTarget(ctx echo.Context) error {
	targetId := ctx.FormValue("id")
	idParam := ctx.Param("id")
	parsedId, _ := strconv.ParseInt(idParam, 10, 64)

	targetContents, err := ctx.FormFile("contents")
	if err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not parse file contents"))
	}
	file, err := targetContents.Open()
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not open file contents"))
	}
	defer file.Close()

	writer, err := s.targets.Update(targetId)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not open target file"))
	}
	defer writer.Close()

	newlineCounter := &targets.NewLineCountWriter{}

	// Merge two writers to write to file as well as count newlines
	finalWriter := io.MultiWriter(writer, newlineCounter)
	_, err = io.Copy(finalWriter, file)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not write to target file"))
	}

	err = s.db.Queries().UpdateTargetMetadata(context.Background(), dbsql.UpdateTargetMetadataParams{
		ID:    parsedId,
		Total: sql.NullInt64{Int64: newlineCounter.Total, Valid: true},
	})
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not update target metadata"))
	}
	return nil
}

// DeleteTarget handles /targets delete route
func (s *Server) DeleteTarget(ctx echo.Context) error {
	idParam := ctx.Param("id")
	parsedId, err := strconv.ParseInt(idParam, 10, 64)
	if err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not parse target id"))
	}

	targetID, err := s.db.Queries().GetTarget(context.Background(), parsedId)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get target from db"))
	}
	err = s.targets.Delete(targetID.Internalid.String)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not delete target from db"))
	}

	err = s.db.Queries().DeleteTarget(context.Background(), parsedId)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not delete target file"))
	}
	return nil
}

// GetTargetContents handles /targets get contents route
func (s *Server) GetTargetContents(ctx echo.Context) error {
	idParam := ctx.Param("id")
	parsedId, err := strconv.ParseInt(idParam, 10, 64)
	if err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not parse target id"))
	}

	targetID, err := s.db.Queries().GetTarget(context.Background(), parsedId)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get target from db"))
	}
	reader, err := s.targets.Read(targetID.Internalid.String)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not read target file"))
	}
	_, err = io.Copy(ctx.Response().Writer, reader)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not copy target file"))
	}
	return nil
}
