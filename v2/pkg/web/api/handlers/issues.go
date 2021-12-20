package handlers

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
)

// AddIssueRequest is a request for /issues addition
type AddIssueRequest struct {
	ScanID        int64     `json:"scanId"`
	Matchedat     string    `json:"matchedAt"`
	Title         string    `json:"title"`
	Severity      string    `json:"severity"`
	Scansource    string    `json:"scanSource"`
	Issuestate    string    `json:"issueState"`
	Description   string    `json:"description"`
	Author        string    `json:"author"`
	Cvss          float64   `json:"cvss"`
	Cwe           []int32   `json:"cwe"`
	Labels        []string  `json:"labels"`
	Issuedata     string    `json:"issueData"`
	Issuetemplate string    `json:"issueTemplate"`
	Templatename  string    `json:"templateName"`
	Remediation   string    `json:"remediation"`
	Createdat     time.Time `json:"createdAt"`
	Updatedat     time.Time `json:"updatedAt"`
}

// AddIssue handlers /issues addition route
func (s *Server) AddIssue(ctx echo.Context) error {
	var req AddIssueRequest
	if err := jsoniter.NewDecoder(ctx.Request().Body).Decode(&req); err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not unmarshal body").Error())
	}

	id, err := s.db.AddIssue(context.Background(), dbsql.AddIssueParams{
		Scanid:        req.ScanID,
		Matchedat:     req.Matchedat,
		Title:         req.Title,
		Severity:      req.Severity,
		Scansource:    req.Scansource,
		Issuestate:    req.Issuestate,
		Description:   req.Description,
		Author:        req.Author,
		Cvss:          sql.NullFloat64{Float64: req.Cvss, Valid: true},
		Cwe:           req.Cwe,
		Labels:        req.Labels,
		Issuedata:     req.Issuedata,
		Issuetemplate: req.Issuetemplate,
		Templatename:  req.Templatename,
		Remediation:   sql.NullString{String: req.Remediation, Valid: true},
	})
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not add issue to db").Error())
	}
	return ctx.JSON(200, map[string]int64{"id": id})
}

// GetIssuesResponse is a response for /issues request
type GetIssuesResponse struct {
	ID            int64     `json:"id,omitempty"`
	ScanID        int64     `json:"scanId,omitempty"`
	Matchedat     string    `json:"matchedAt,omitempty"`
	Title         string    `json:"title,omitempty"`
	Severity      string    `json:"severity,omitempty"`
	Scansource    string    `json:"scanSource,omitempty"`
	Issuestate    string    `json:"issueState,omitempty"`
	Description   string    `json:"description,omitempty"`
	Author        string    `json:"author,omitempty"`
	Cvss          float64   `json:"cvss,omitempty"`
	Cwe           []int32   `json:"cwe,omitempty"`
	Labels        []string  `json:"labels,omitempty"`
	Issuedata     string    `json:"issueData,omitempty"`
	Issuetemplate string    `json:"issueTemplate,omitempty"`
	Templatename  string    `json:"templateName,omitempty"`
	Remediation   string    `json:"remediation,omitempty"`
	Createdat     time.Time `json:"createdAt,omitempty"`
	Updatedat     time.Time `json:"updatedAt,omitempty"`
}

// GetIssues handlers /issues getting route
func (s *Server) GetIssues(ctx echo.Context) error {
	response, err := s.db.GetIssues(context.Background())
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get issues fromdb").Error())
	}
	targets := make([]GetIssuesResponse, len(response))
	for i, value := range response {
		targets[i] = GetIssuesResponse{
			ID:         value.ID,
			ScanID:     value.Scanid,
			Matchedat:  value.Matchedat,
			Title:      value.Title,
			Severity:   value.Severity,
			Createdat:  value.Createdat,
			Updatedat:  value.Updatedat,
			Scansource: value.Scansource,
		}
	}
	return ctx.JSON(200, targets)
}

// GetIssue handlers /issues/:id getting route
func (s *Server) GetIssue(ctx echo.Context) error {
	queryParam := ctx.Param("id")
	id, err := strconv.ParseInt(queryParam, 10, 64)
	if err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not parse issue id").Error())
	}
	scan, err := s.db.GetIssue(context.Background(), id)
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get issue from db").Error())
	}
	value := GetIssuesResponse{
		ID:            scan.ID,
		ScanID:        scan.Scanid,
		Matchedat:     scan.Matchedat,
		Title:         scan.Title,
		Severity:      scan.Severity,
		Scansource:    scan.Scansource,
		Issuestate:    scan.Issuestate,
		Description:   scan.Description,
		Author:        scan.Author,
		Cvss:          scan.Cvss.Float64,
		Cwe:           scan.Cwe,
		Labels:        scan.Labels,
		Issuedata:     scan.Issuedata,
		Issuetemplate: scan.Issuetemplate,
		Templatename:  scan.Templatename,
		Remediation:   scan.Remediation.String,
		Createdat:     scan.Createdat,
		Updatedat:     scan.Updatedat,
	}
	return ctx.JSON(200, value)
}

// UpdateIssueRequest is a request for /issues/:id update request
type UpdateIssueRequest struct {
	State string `json:"state"`
}

// UpdateIssue handlers /issues/:id updating route
func (s *Server) UpdateIssue(ctx echo.Context) error {
	var req UpdateIssueRequest
	if err := jsoniter.NewDecoder(ctx.Request().Body).Decode(&req); err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not unmarshal body").Error())
	}
	queryParam := ctx.Param("id")
	id, err := strconv.ParseInt(queryParam, 10, 64)
	if err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not parse issue id").Error())
	}
	err = s.db.UpdateIssue(context.Background(), dbsql.UpdateIssueParams{
		ID:         id,
		Issuestate: req.State,
	})
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not update issue").Error())
	}
	return nil
}

// DeleteIssue handlers /issues/:id deletion route
func (s *Server) DeleteIssue(ctx echo.Context) error {
	queryParam := ctx.Param("id")
	id, err := strconv.ParseInt(queryParam, 10, 64)
	if err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not parse issue id").Error())
	}
	if err := s.db.DeleteIssue(context.Background(), id); err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not delete issue").Error())
	}
	return nil
}
