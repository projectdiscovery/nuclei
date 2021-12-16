package handlers

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo/v4"
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
		return err
	}

	err := s.db.Queries().AddIssue(context.Background(), dbsql.AddIssueParams{
		Scanid:        sql.NullInt64{Int64: req.ScanID, Valid: true},
		Matchedat:     sql.NullString{String: req.Matchedat, Valid: true},
		Title:         sql.NullString{String: req.Title, Valid: true},
		Severity:      sql.NullString{String: req.Severity, Valid: true},
		Scansource:    sql.NullString{String: req.Scansource, Valid: true},
		Issuestate:    sql.NullString{String: req.Issuestate, Valid: true},
		Description:   sql.NullString{String: req.Description, Valid: true},
		Author:        sql.NullString{String: req.Author, Valid: true},
		Cvss:          sql.NullFloat64{Float64: req.Cvss, Valid: true},
		Cwe:           req.Cwe,
		Labels:        req.Labels,
		Issuedata:     sql.NullString{String: req.Issuedata, Valid: true},
		Issuetemplate: sql.NullString{String: req.Issuetemplate, Valid: true},
		Templatename:  sql.NullString{String: req.Templatename, Valid: true},
		Remediation:   sql.NullString{String: req.Remediation, Valid: true},
	})
	return err
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
	response, err := s.db.Queries().GetIssues(context.Background())
	if err != nil {
		return err
	}
	targets := make([]GetIssuesResponse, len(response))
	for i, value := range response {
		targets[i] = GetIssuesResponse{
			ID:         value.ID,
			ScanID:     value.Scanid.Int64,
			Matchedat:  value.Matchedat.String,
			Title:      value.Title.String,
			Severity:   value.Severity.String,
			Createdat:  value.Createdat.Time,
			Updatedat:  value.Updatedat.Time,
			Scansource: value.Scansource.String,
		}
	}
	return ctx.JSON(200, targets)
}

// GetIssue handlers /issues/:id getting route
func (s *Server) GetIssue(ctx echo.Context) error {
	queryParam := ctx.Param("id")
	id, err := strconv.ParseInt(queryParam, 10, 64)
	if err != nil {
		return err
	}
	scan, err := s.db.Queries().GetIssue(context.Background(), id)
	if err != nil {
		return err
	}
	value := GetIssuesResponse{
		ID:            scan.ID,
		ScanID:        scan.Scanid.Int64,
		Matchedat:     scan.Matchedat.String,
		Title:         scan.Title.String,
		Severity:      scan.Severity.String,
		Scansource:    scan.Scansource.String,
		Issuestate:    scan.Issuestate.String,
		Description:   scan.Description.String,
		Author:        scan.Author.String,
		Cvss:          scan.Cvss.Float64,
		Cwe:           scan.Cwe,
		Labels:        scan.Labels,
		Issuedata:     scan.Issuedata.String,
		Issuetemplate: scan.Issuetemplate.String,
		Templatename:  scan.Templatename.String,
		Remediation:   scan.Remediation.String,
		Createdat:     scan.Createdat.Time,
		Updatedat:     scan.Updatedat.Time,
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
		return err
	}
	queryParam := ctx.Param("id")
	id, err := strconv.ParseInt(queryParam, 10, 64)
	if err != nil {
		return err
	}
	s.db.Queries().UpdateIssue(context.Background(), dbsql.UpdateIssueParams{
		ID:         id,
		Issuestate: sql.NullString{String: req.State, Valid: true},
	})
	return nil
}

// DeleteIssue handlers /issues/:id deletion route
func (s *Server) DeleteIssue(ctx echo.Context) error {
	queryParam := ctx.Param("id")
	id, err := strconv.ParseInt(queryParam, 10, 64)
	if err != nil {
		return err
	}
	if err := s.db.Queries().DeleteIssue(context.Background(), id); err != nil {
		return err
	}
	return nil
}
