package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/handlers"
)

// API is a REST API server structure
type API struct {
	echo *echo.Echo
}

// Config contains configuration options for REST API
type Config struct {
	Userame  string
	Password string
	Host     string
	Port     int
	TLS      bool
	Server   *handlers.Server
}

// New returns a new REST API server structure
func New(config *Config) *API {
	// Echo instance
	e := echo.New()
	e.JSONSerializer = &JSONIterSerializer{}

	scheme := "http"
	if config.TLS {
		scheme = "https"
	}

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{fmt.Sprintf("%s://%s:%d", scheme, config.Host, config.Port)},
		AllowMethods:     []string{echo.GET, echo.HEAD, echo.PUT, echo.PATCH, echo.POST, echo.DELETE},
		AllowCredentials: true,
		AllowHeaders:     []string{"Authorization"},
	}))
	// Use basic auth
	e.Use(middleware.BasicAuth(func(user, password string, ctx echo.Context) (bool, error) {
		if user != config.Userame || password != config.Password {
			return false, nil
		}
		return true, nil
	}))

	apiGroup := e.Group("/api/v1")

	// /templates endpoints
	apiGroup.GET("/templates", config.Server.GetTemplates)
	apiGroup.POST("/templates", config.Server.AddTemplate)
	apiGroup.PUT("/templates", config.Server.UpdateTemplate)
	apiGroup.DELETE("/templates", config.Server.DeleteTemplate)
	apiGroup.GET("/templates/raw", config.Server.GetTemplatesRaw)
	apiGroup.POST("/templates/execute", config.Server.ExecuteTemplate)

	// /targets endpoints
	apiGroup.GET("/targets", config.Server.GetTargets)
	apiGroup.POST("/targets", config.Server.AddTarget)
	apiGroup.PUT("/targets/:id", config.Server.UpdateTarget)
	apiGroup.DELETE("/targets/:id", config.Server.DeleteTarget)
	apiGroup.GET("/targets/:id", config.Server.GetTargetContents)

	// /settings endpoints
	apiGroup.GET("/settings", config.Server.GetSettings)
	apiGroup.POST("/settings", config.Server.SetSetting)
	apiGroup.GET("/settings/:name", config.Server.GetSettingByName)
	apiGroup.PUT("/settings/:name", config.Server.UpdateSettingByName)

	// /scans endpoints
	//apiGroup.GET("/scans", config.Server.GetScans)
	//apiGroup.POST("/scans", config.Server.AddScan)
	//	apiGroup.PUT("/scans/:id", config.Server.UpdateScan)
	//	apiGroup.DELETE("/scans/:id", config.Server.DeleteScan)
	//	apiGroup.GET("/scans/:id", config.Server.GetScan)
	//	apiGroup.GET("/scans/:id/matches", config.Server.GetScanMatches)
	//	apiGroup.GET("/scans/:id/errors", config.Server.GetScanErrors)
	//	apiGroup.GET("/scans/:id/debug", config.Server.GetScanDebug)

	return &API{echo: e}
}

// JSONIterSerializer implements JSON encoding using jsoniter for echo.
type JSONIterSerializer struct{}

// Serialize converts an interface into a json and writes it to the response.
// You can optionally use the indent parameter to produce pretty JSONs.
func (d JSONIterSerializer) Serialize(c echo.Context, i interface{}, indent string) error {
	enc := jsoniter.NewEncoder(c.Response())
	if indent != "" {
		enc.SetIndent("", indent)
	}
	return enc.Encode(i)
}

// Deserialize reads a JSON from a request body and converts it into an interface.
func (d JSONIterSerializer) Deserialize(c echo.Context, i interface{}) error {
	err := jsoniter.NewDecoder(c.Request().Body).Decode(i)
	if ute, ok := err.(*json.UnmarshalTypeError); ok {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Unmarshal type error: expected=%v, got=%v, field=%v, offset=%v", ute.Type, ute.Value, ute.Field, ute.Offset)).SetInternal(err)
	} else if se, ok := err.(*json.SyntaxError); ok {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Syntax error: offset=%v, error=%v", se.Offset, se.Error())).SetInternal(err)
	}
	return err
}
