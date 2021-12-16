package handlers

import (
	"context"
	"database/sql"
	"io"
	"strconv"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo/v4"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/scans"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
)

// AddScanRequest is a request for /scans addition
type AddScanRequest struct {
	Name              string   `json:"name"`
	Templates         []string `json:"templates"`
	Targets           []string `json:"targets"`
	Config            string   `json:"config"` // nuclei config, default -> "default"
	RunNow            bool     `json:"run-now"`
	Reporting         string   `json:"reporting-config"`
	ScheduleOccurence string   `json:"schedule-occurence"`
	ScheduleTime      string   `json:"schedule-time"`
	ScanSource        string   `json:"scanSource"`
}

// AddScan handlers /scans addition route
func (s *Server) AddScan(ctx echo.Context) error {
	var req AddScanRequest
	if err := jsoniter.NewDecoder(ctx.Request().Body).Decode(&req); err != nil {
		return err
	}

	targets := make([]string, len(req.Targets))
	for i, value := range req.Targets {
		targets[i] = value
	}
	hostCount := scans.CalculateTargetCount(req.Targets, s.db)
	id, err := s.db.Queries().AddScan(context.Background(), dbsql.AddScanParams{
		Name:              sql.NullString{String: req.Name, Valid: true},
		Status:            sql.NullString{String: "scheduled", Valid: true},
		Hosts:             sql.NullInt64{Int64: hostCount, Valid: true},
		Scansource:        sql.NullString{String: req.ScanSource, Valid: true},
		Templates:         req.Templates,
		Targets:           targets,
		Config:            sql.NullString{String: req.Config, Valid: true},
		Runnow:            sql.NullBool{Bool: req.RunNow, Valid: true},
		Reporting:         sql.NullString{String: req.Reporting, Valid: true},
		Scheduleoccurence: sql.NullString{String: req.ScheduleOccurence, Valid: true},
		Scheduletime:      sql.NullString{String: req.ScheduleTime, Valid: true},
	})

	if req.RunNow {
		s.scans.Queue(scans.ScanRequest{
			ScanID:    id,
			Templates: req.Templates,
			Targets:   req.Targets,
			Config:    req.Config,
			RunNow:    req.RunNow,
			Reporting: req.Reporting,
		})
	}
	return err
}

// GetScanResponse is a response for /scans request
type GetScanResponse struct {
	ID                int64         `json:"id"`
	Status            string        `json:"status"`
	Name              string        `json:"name"`
	Templates         []string      `json:"templates"`
	Targets           []string      `json:"targets"`
	Config            string        `json:"config"` // nuclei config, default -> "default"
	RunNow            bool          `json:"run-now"`
	Reporting         string        `json:"reporting-config"`
	ScheduleOccurence string        `json:"schedule-occurence"`
	ScheduleTime      string        `json:"schedule-time"`
	ScanSource        string        `json:"scanSource"`
	ScanTime          time.Duration `json:"scanTime"`
	Hosts             int64         `json:"hosts"`
}

// GetScans handlers /scans getting route
func (s *Server) GetScans(ctx echo.Context) error {
	var response []dbsql.Scan
	var err error
	if searchKey := ctx.QueryParam("search"); searchKey != "" {
		response, err = s.db.Queries().GetScansBySearchKey(context.Background(), sql.NullString{String: searchKey, Valid: true})
	} else {
		response, err = s.db.Queries().GetScans(context.Background())
	}
	if err != nil {
		return err
	}
	targets := make([]GetScanResponse, len(response))
	for i, value := range response {
		targets[i] = GetScanResponse{
			ID:                value.ID,
			Status:            value.Status.String,
			Name:              value.Name.String,
			Templates:         value.Templates,
			Targets:           value.Targets,
			Config:            value.Config.String,
			RunNow:            value.Runnow.Bool,
			Reporting:         value.Reporting.String,
			ScheduleOccurence: value.Scheduleoccurence.String,
			ScheduleTime:      value.Scheduletime.String,
			ScanSource:        value.Scansource.String,
			ScanTime:          time.Duration(value.Scantime.Int64),
			Hosts:             value.Hosts.Int64,
		}
	}
	return ctx.JSON(200, targets)
}

// GetScan handlers /scans/:id getting route
func (s *Server) GetScan(ctx echo.Context) error {
	queryParam := ctx.Param("id")
	id, err := strconv.ParseInt(queryParam, 10, 64)
	if err != nil {
		return err
	}
	scan, err := s.db.Queries().GetScan(context.Background(), id)
	if err != nil {
		return err
	}
	value := GetScanResponse{
		ID:                scan.ID,
		Status:            scan.Status.String,
		Name:              scan.Name.String,
		Templates:         scan.Templates,
		Targets:           scan.Targets,
		Config:            scan.Config.String,
		RunNow:            scan.Runnow.Bool,
		Reporting:         scan.Reporting.String,
		ScheduleOccurence: scan.Scheduleoccurence.String,
		ScheduleTime:      scan.Scheduletime.String,
		ScanSource:        scan.Scansource.String,
		ScanTime:          time.Duration(scan.Scantime.Int64),
		Hosts:             scan.Hosts.Int64,
	}
	return ctx.JSON(200, value)
}

// GetScanProgress handlers /scans/progress getting route
func (s *Server) GetScanProgress(ctx echo.Context) error {
	return ctx.JSON(200, s.scans.Progress())
}

// GetScanMatchesResponse is a response for /scans/:id/matches response
type GetScanMatchesResponse struct {
	TemplateName string `json:"templateName"`
	Severity     string `json:"severity"`
	Author       string `json:"author"`
	MatchedAt    string `json:"matchedAt"`
}

// GetScanMatches handlers /scans/:id/matches listing route
func (s *Server) GetScanMatches(ctx echo.Context) error {
	queryParam := ctx.Param("id")
	id, err := strconv.ParseInt(queryParam, 10, 64)
	if err != nil {
		return err
	}
	rows, err := s.db.Queries().GetIssuesMatches(context.Background(), sql.NullInt64{Int64: id})
	if err != nil {
		return err
	}
	response := make([]GetScanMatchesResponse, len(rows))
	for i, row := range rows {
		response[i] = GetScanMatchesResponse{
			TemplateName: row.Templatename.String,
			Severity:     row.Severity.String,
			Author:       row.Author.String,
			MatchedAt:    row.Matchedat.String,
		}
	}
	return ctx.JSON(200, response)
}

// UpdateScanRequest is a request for /scans/:id update request
type UpdateScanRequest struct {
	Pause        bool `json:"pause"`
	Stop         bool `json:"stop"`
	Resume       bool `json:"resume"`
	ScheduleTime bool `json:"scheduleTime"`
}

// UpdateScan handlers /scans/:id updating route
func (s *Server) UpdateScan(ctx echo.Context) error {
	var req UpdateScanRequest
	if err := jsoniter.NewDecoder(ctx.Request().Body).Decode(&req); err != nil {
		return err
	}
	queryParam := ctx.Param("id")
	id, err := strconv.ParseInt(queryParam, 10, 64)
	if err != nil {
		return err
	}
	_ = id
	// todo: Handle pause resume update and time update
	return nil
}

// DeleteScan handlers /scans/:id deletion route
func (s *Server) DeleteScan(ctx echo.Context) error {
	var req UpdateScanRequest
	if err := jsoniter.NewDecoder(ctx.Request().Body).Decode(&req); err != nil {
		return err
	}
	queryParam := ctx.Param("id")
	id, err := strconv.ParseInt(queryParam, 10, 64)
	if err != nil {
		return err
	}
	err = s.db.Queries().DeleteScan(context.Background(), id)
	deleteErr := s.db.Queries().DeleteIssueByScanID(context.Background(), sql.NullInt64{Int64: id, Valid: true})
	if err != nil || deleteErr != nil {
		return echo.NewHTTPError(500, err, deleteErr)
	}
	return nil
}

// GetScanErrors handlers /scans/:id/errors listing route
func (s *Server) GetScanErrors(ctx echo.Context) error {
	queryParam := ctx.Param("id")
	id, err := strconv.ParseInt(queryParam, 10, 64)
	if err != nil {
		return err
	}
	logsReader, err := s.scans.Logs.Read(id)
	if err != nil {
		return err
	}
	defer logsReader.Close()

	_, _ = io.Copy(ctx.Response().Writer, logsReader)
	return nil
}
