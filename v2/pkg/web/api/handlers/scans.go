package handlers

import (
	"context"
	"database/sql"
	"io"
	"strconv"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/scans"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
)

// AddScanRequest is a request for /scans addition
type AddScanRequest struct {
	Name              string   `json:"name"`
	Templates         []string `json:"templates"`
	Targets           []string `json:"targets"`
	Config            string   `json:"config"` // nuclei config, default -> "default"
	RunNow            bool     `json:"runNow"`
	Reporting         string   `json:"reportingConfig"`
	ScheduleOccurence string   `json:"scheduleOccurence"`
	ScheduleTime      string   `json:"scheduleTime"`
	ScanSource        string   `json:"scanSource"`
}

// AddScan handlers /scans addition route
func (s *Server) AddScan(ctx echo.Context) error {
	var req AddScanRequest
	if err := jsoniter.NewDecoder(ctx.Request().Body).Decode(&req); err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not unmarshal body").Error())
	}

	targets := make([]string, len(req.Targets))
	for i, value := range req.Targets {
		targets[i] = value
	}
	hostCount := scans.CalculateTargetCount(req.Targets, s.db)
	id, err := s.db.AddScan(context.Background(), dbsql.AddScanParams{
		Name:              req.Name,
		Status:            "scheduled",
		Hosts:             hostCount,
		Scansource:        req.ScanSource,
		Templates:         req.Templates,
		Targets:           targets,
		Config:            sql.NullString{String: req.Config, Valid: true},
		Runnow:            sql.NullBool{Bool: req.RunNow, Valid: true},
		Reporting:         sql.NullString{String: req.Reporting, Valid: true},
		Scheduleoccurence: sql.NullString{String: req.ScheduleOccurence, Valid: true},
		Scheduletime:      sql.NullString{String: req.ScheduleTime, Valid: true},
	})
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not add scan to db").Error())
	}
	if req.RunNow {
		s.scans.Queue(scans.ScanRequest{
			ScanID:     id,
			ScanSource: req.ScanSource,
			Templates:  req.Templates,
			Targets:    req.Targets,
			Config:     req.Config,
			RunNow:     req.RunNow,
			Reporting:  req.Reporting,
		})
	}
	return ctx.JSON(200, map[string]int64{"id": id})
}

// GetScanResponse is a response for /scans request
type GetScanResponse struct {
	ID                int64         `json:"id,omitempty"`
	Status            string        `json:"status,omitempty"`
	Name              string        `json:"name,omitempty"`
	Templates         []string      `json:"templates,omitempty"`
	Targets           []string      `json:"targets,omitempty"`
	Config            string        `json:"config,omitempty"` // nuclei config, default -> "default"
	RunNow            bool          `json:"runNow,omitempty"`
	Reporting         string        `json:"reportingConfig,omitempty"`
	ScheduleOccurence string        `json:"scheduleOccurence,omitempty"`
	ScheduleTime      string        `json:"scheduleTime,omitempty"`
	ScanSource        string        `json:"scanSource,omitempty"`
	ScanTime          time.Duration `json:"scanTime,omitempty"`
	Hosts             int64         `json:"hosts,omitempty"`
}

// GetScans handlers /scans getting route
func (s *Server) GetScans(ctx echo.Context) error {
	var response []dbsql.Scan
	var err error
	if searchKey := ctx.QueryParam("search"); searchKey != "" {
		response, err = s.db.GetScansBySearchKey(context.Background(), sql.NullString{String: searchKey, Valid: true})
	} else {
		response, err = s.db.GetScans(context.Background())
	}
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get scans from db").Error())
	}
	targets := make([]GetScanResponse, len(response))
	for i, value := range response {
		targets[i] = GetScanResponse{
			ID:                value.ID,
			Status:            value.Status,
			Name:              value.Name,
			Templates:         value.Templates,
			Targets:           value.Targets,
			Config:            value.Config.String,
			RunNow:            value.Runnow.Bool,
			Reporting:         value.Reporting.String,
			ScheduleOccurence: value.Scheduleoccurence.String,
			ScheduleTime:      value.Scheduletime.String,
			ScanSource:        value.Scansource,
			ScanTime:          time.Duration(value.Scantime),
			Hosts:             value.Hosts,
		}
	}
	return ctx.JSON(200, targets)
}

// GetScan handlers /scans/:id getting route
func (s *Server) GetScan(ctx echo.Context) error {
	queryParam := ctx.Param("id")
	id, err := strconv.ParseInt(queryParam, 10, 64)
	if err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not parse scan id").Error())
	}
	scan, err := s.db.GetScan(context.Background(), id)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get scan from db").Error())
	}
	value := GetScanResponse{
		ID:                scan.ID,
		Status:            scan.Status,
		Name:              scan.Name,
		Templates:         scan.Templates,
		Targets:           scan.Targets,
		Config:            scan.Config.String,
		RunNow:            scan.Runnow.Bool,
		Reporting:         scan.Reporting.String,
		ScheduleOccurence: scan.Scheduleoccurence.String,
		ScheduleTime:      scan.Scheduletime.String,
		ScanSource:        scan.Scansource,
		ScanTime:          time.Duration(scan.Scantime),
		Hosts:             scan.Hosts,
	}
	return ctx.JSON(200, value)
}

// GetScanProgress handlers /scans/progress getting route
func (s *Server) GetScanProgress(ctx echo.Context) error {
	return ctx.JSON(200, s.scans.Progress())
}

// ExecuteScan handlers /scans/:id/execute execution route
func (s *Server) ExecuteScan(ctx echo.Context) error {
	queryParam := ctx.Param("id")
	id, err := strconv.ParseInt(queryParam, 10, 64)
	if err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not parse scan id").Error())
	}
	scan, err := s.db.GetScan(context.Background(), id)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get scan from db").Error())
	}
	s.scans.Queue(scans.ScanRequest{
		ScanID:    id,
		Templates: scan.Templates,
		Targets:   scan.Targets,
		Config:    scan.Config.String,
		Reporting: scan.Reporting.String,
	})
	return nil
}

// GetScanMatchesResponse is a response for /scans/:id/matches response
type GetScanMatchesResponse struct {
	TemplateName string `json:"templateName,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Author       string `json:"author,omitempty"`
	MatchedAt    string `json:"matchedAt,omitempty"`
}

// GetScanMatches handlers /scans/:id/matches listing route
func (s *Server) GetScanMatches(ctx echo.Context) error {
	queryParam := ctx.Param("id")
	id, err := strconv.ParseInt(queryParam, 10, 64)
	if err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not parse scan id").Error())
	}
	rows, err := s.db.GetIssuesMatches(context.Background(), id)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get scan matches from db").Error())
	}
	response := make([]GetScanMatchesResponse, len(rows))
	for i, row := range rows {
		response[i] = GetScanMatchesResponse{
			TemplateName: row.Templatename,
			Severity:     row.Severity,
			Author:       row.Author,
			MatchedAt:    row.Matchedat,
		}
	}
	return ctx.JSON(200, response)
}

// UpdateScanRequest is a request for /scans/:id update request
type UpdateScanRequest struct {
	Stop bool `json:"stop"`

	// Pause        bool `json:"pause"`
	// Resume       bool `json:"resume"`
	// ScheduleTime bool `json:"scheduleTime"`
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
		return echo.NewHTTPError(400, errors.Wrap(err, "could not parse scan id").Error())
	}
	value, ok := s.scans.Running.Load(id)
	if !ok {
		return echo.NewHTTPError(400, errors.New("could not get running scan").Error())
	}
	runningScan := value.(*scans.RunningScan)

	if req.Stop {
		runningScan.Stop()
	}
	return nil
}

// DeleteScan handlers /scans/:id deletion route
func (s *Server) DeleteScan(ctx echo.Context) error {
	queryParam := ctx.Param("id")
	id, err := strconv.ParseInt(queryParam, 10, 64)
	if err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not parse scan id").Error())
	}
	err = s.db.DeleteScan(context.Background(), id)
	deleteErr := s.db.DeleteIssueByScanID(context.Background(), id)
	if deleteErr != nil {
		return echo.NewHTTPError(500, errors.Wrap(deleteErr, "could not delete issues").Error())
	}
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not delete scan").Error())
	}
	return nil
}

// GetScanErrors handlers /scans/:id/errors listing route
func (s *Server) GetScanErrors(ctx echo.Context) error {
	ctx.Response().Header().Set("Content-Type", echo.MIMEApplicationJSONCharsetUTF8)

	queryParam := ctx.Param("id")
	id, err := strconv.ParseInt(queryParam, 10, 64)
	if err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not parse scan id").Error())
	}
	logsReader, err := s.scans.Logs.Read(id)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not read scans errors").Error())
	}
	defer logsReader.Close()

	_, _ = io.Copy(ctx.Response().Writer, logsReader)
	return nil
}
