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
	targets, err := s.db.GetTargets(context.Background())
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get targets from db").Error())
	}
	targetsList := make([]GetTargetsResponse, 0, len(targets))
	for _, target := range targets {
		targetsList = append(targetsList, GetTargetsResponse{
			ID:         target.ID,
			Name:       target.Name,
			Createdat:  target.Createdat,
			Updatedat:  target.Updatedat,
			Filename:   target.Filename,
			InternalID: target.Internalid,
			Total:      target.Total,
		})
	}
	return ctx.JSON(200, targetsList)
}

// getTargetsWithSearchKey returns targets for a search key
func (s *Server) getTargetsWithSearchKey(ctx echo.Context, searchKey string) error {
	targets, err := s.db.GetTargetsForSearch(context.Background(), sql.NullString{String: searchKey, Valid: true})
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get targets from db").Error())
	}
	targetsList := make([]GetTargetsResponse, 0, len(targets))
	for _, target := range targets {
		targetsList = append(targetsList, GetTargetsResponse{
			ID:         target.ID,
			Name:       target.Name,
			Createdat:  target.Createdat,
			Updatedat:  target.Updatedat,
			Filename:   target.Filename,
			InternalID: target.Internalid,
			Total:      target.Total,
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
		return echo.NewHTTPError(400, errors.Wrap(err, "could not parse file contents").Error())
	}
	file, err := targetContents.Open()
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not open file contents").Error())
	}
	defer file.Close()

	writer, id, err := s.targets.Create()
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not create target file").Error())
	}
	defer writer.Close()

	newlineCounter := &targets.NewLineCountWriter{}

	// Merge two writers to write to file as well as count newlines
	finalWriter := io.MultiWriter(writer, newlineCounter)
	_, err = io.Copy(finalWriter, file)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not write to target file").Error())
	}

	gotID, err := s.db.AddTarget(context.Background(), dbsql.AddTargetParams{
		Name:       targetName,
		Internalid: id,
		Filename:   targetPath,
		Total:      newlineCounter.Total,
	})
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not add target to db").Error())
	}
	return ctx.JSON(200, map[string]int64{"id": gotID})
}

// UpdateTarget handles /targets update route
// It accepts multipart-form format.
func (s *Server) UpdateTarget(ctx echo.Context) error {
	idParam := ctx.Param("id")
	parsedId, err := strconv.ParseInt(idParam, 10, 64)
	if err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not parse target id").Error())
	}

	targetContents, err := ctx.FormFile("contents")
	if err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not parse file contents").Error())
	}
	file, err := targetContents.Open()
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not open file contents").Error())
	}
	defer file.Close()

	targetID, err := s.db.GetTarget(context.Background(), parsedId)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get target from db").Error())
	}

	writer, err := s.targets.Update(targetID.Internalid)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not open target file").Error())
	}
	defer writer.Close()

	_, _ = writer.Write([]byte("\n"))

	newlineCounter := &targets.NewLineCountWriter{}

	// Merge two writers to write to file as well as count newlines
	finalWriter := io.MultiWriter(writer, newlineCounter)
	_, err = io.Copy(finalWriter, file)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not write to target file").Error())
	}

	err = s.db.UpdateTargetMetadata(context.Background(), dbsql.UpdateTargetMetadataParams{
		ID:    parsedId,
		Total: newlineCounter.Total,
	})
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not update target metadata").Error())
	}
	return nil
}

// DeleteTarget handles /targets delete route
func (s *Server) DeleteTarget(ctx echo.Context) error {
	idParam := ctx.Param("id")
	parsedId, err := strconv.ParseInt(idParam, 10, 64)
	if err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not parse target id").Error())
	}

	targetID, err := s.db.GetTarget(context.Background(), parsedId)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get target from db").Error())
	}
	err = s.targets.Delete(targetID.Internalid)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not delete target from db").Error())
	}

	err = s.db.DeleteTarget(context.Background(), parsedId)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not delete target file").Error())
	}
	return nil
}

// GetTargetContents handles /targets get contents route
func (s *Server) GetTargetContents(ctx echo.Context) error {
	idParam := ctx.Param("id")
	parsedId, err := strconv.ParseInt(idParam, 10, 64)
	if err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not parse target id").Error())
	}

	targetID, err := s.db.GetTarget(context.Background(), parsedId)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get target from db").Error())
	}
	reader, err := s.targets.Read(targetID.Internalid)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not read target file").Error())
	}
	_, err = io.Copy(ctx.Response().Writer, reader)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not copy target file").Error())
	}
	return nil
}
