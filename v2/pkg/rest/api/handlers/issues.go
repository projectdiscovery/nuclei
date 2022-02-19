package handlers

import (
	"context"
	"strconv"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/db/dbsql"
)

// AddIssueRequest is a request for /issues addition
type AddIssueRequest struct {
	// tbd
}

// AddIssue handlers /issues addition route
func (s *Server) AddIssue(ctx echo.Context) error {
	var req AddIssueRequest
	if err := jsoniter.NewDecoder(ctx.Request().Body).Decode(&req); err != nil {
		return echo.NewHTTPError(400, errors.Wrap(err, "could not unmarshal body").Error())
	}
	return ctx.JSON(200, map[string]int64{"id": -1})
}

// GetIssuesResponse is a response for /issues request
type GetIssuesResponse struct {
	Template         string    `json:"template,omitempty"`
	Templateurl      string    `json:"templateUrl,omitempty"`
	Templateid       string    `json:"templateId,omitempty"`
	Templatepath     string    `json:"templatePath,omitempty"`
	Templatename     string    `json:"templateName,omitempty"`
	Author           string    `json:"author,omitempty"`
	Labels           []string  `json:"labels,omitempty"`
	Description      string    `json:"description,omitempty"`
	Reference        []string  `json:"reference,omitempty"`
	Severity         string    `json:"severity,omitempty"`
	Templatemetadata string    `json:"templatemetadata,omitempty"`
	Cvss             float64   `json:"cvss,omitempty"`
	Cwe              []int32   `json:"cwe,omitempty"`
	Cveid            string    `json:"cveid,omitempty"`
	Cvssmetrics      string    `json:"cvssmetrics,omitempty"`
	Remediation      string    `json:"remediation,omitempty"`
	Matchername      string    `json:"matcherName,omitempty"`
	Extractorname    string    `json:"extractorName,omitempty"`
	Resulttype       string    `json:"resultType,omitempty"`
	Host             string    `json:"host,omitempty"`
	Path             string    `json:"path,omitempty"`
	Matchedat        string    `json:"matchedAt,omitempty"`
	Extractedresults []string  `json:"extractedResults,omitempty"`
	Request          string    `json:"request,omitempty"`
	Response         string    `json:"response,omitempty"`
	Metadata         string    `json:"metadata,omitempty"`
	Ip               string    `json:"ip,omitempty"`
	Interaction      string    `json:"interaction,omitempty"`
	Curlcommand      string    `json:"curlCommand,omitempty"`
	Matcherstatus    bool      `json:"matcherStatus,omitempty"`
	Title            string    `json:"title,omitempty"`
	Createdat        time.Time `json:"createdAt,omitempty"`
	Updatedat        time.Time `json:"updatedAt,omitempty"`
	Scansource       string    `json:"scanSource,omitempty"`
	Issuestate       string    `json:"issueState,omitempty"`
	Hash             string    `json:"hash,omitempty"`
	ID               int64     `json:"id,omitempty"`
	Scanid           int64     `json:"scanId,omitempty"`
}

// GetIssues handlers /issues getting route
func (s *Server) GetIssues(ctx echo.Context) error {
	page, size := paginationDataFromContext(ctx)

	response, err := s.db.GetIssues(context.Background(), dbsql.GetIssuesParams{
		SqlOffset: page,
		SqlLimit:  size,
	})
	if err != nil {
		return echo.NewHTTPError(500, errors.Wrap(err, "could not get issues fromdb").Error())
	}
	targets := make([]GetIssuesResponse, len(response))
	for i, value := range response {
		targets[i] = GetIssuesResponse{
			ID:         value.ID,
			Scanid:     value.Scanid,
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
		Templateurl:      scan.Templateurl.String,
		Templateid:       scan.Templateid.String,
		Template:         scan.Template,
		Templatepath:     scan.Templatepath.String,
		Templatename:     scan.Templatename,
		Author:           scan.Author.String,
		Labels:           scan.Labels,
		Description:      scan.Description,
		Reference:        scan.Reference,
		Severity:         scan.Severity,
		Templatemetadata: scan.Templatemetadata.String,
		Cvss:             scan.Cvss.Float64,
		Cwe:              scan.Cwe,
		Cveid:            scan.Cveid.String,
		Cvssmetrics:      scan.Cvssmetrics.String,
		Remediation:      scan.Remediation.String,
		Matchername:      scan.Matchername.String,
		Extractorname:    scan.Extractorname.String,
		Resulttype:       scan.Resulttype,
		Host:             scan.Host,
		Path:             scan.Path.String,
		Matchedat:        scan.Matchedat,
		Extractedresults: scan.Extractedresults,
		Request:          scan.Request.String,
		Response:         scan.Response.String,
		Metadata:         scan.Metadata.String,
		Ip:               scan.Ip.String,
		Interaction:      scan.Interaction.String,
		Curlcommand:      scan.Curlcommand.String,
		Matcherstatus:    scan.Matcherstatus.Bool,
		Title:            scan.Title,
		Createdat:        scan.Createdat,
		Updatedat:        scan.Updatedat,
		Scansource:       scan.Scansource,
		Issuestate:       scan.Issuestate,
		Hash:             scan.Hash,
		ID:               scan.ID,
		Scanid:           scan.Scanid,
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
