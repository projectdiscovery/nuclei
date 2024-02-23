package main

import (
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/projectdiscovery/retryablehttp-go"
)

func main() {
	e := echo.New()
	e.Use(middleware.Recover())
	e.Use(middleware.Logger())

	e.GET("/", indexHandler)
	e.GET("/info", infoHandler)
	e.GET("/redirect", redirectHandler)
	e.GET("/request", requestHandler)
	e.GET("/email", emailHandler)
	e.GET("/permissions", permissionsHandler)
	e.GET("/blog/post", numIdorHandler) // for num based idors like ?id=44
	e.POST("/reset-password", resetPasword)
	e.GET("/host-header-lab", hostHeaderLab)
	if err := e.Start("localhost:8082"); err != nil {
		panic(err)
	}
}

var bodyTemplate = `<html>
<head>
<title>Fuzz Playground</title>
</head>
<body>
%s
</body>
</html>`

func indexHandler(ctx echo.Context) error {
	return ctx.HTML(200, fmt.Sprintf(bodyTemplate, `<h1>Fuzzing Playground</h1><hr>
<ul>
<li><a href="/info?name=test&another=value&random=data">Info Page XSS</a></li>
<li><a href="/redirect?redirect_url=/info?name=redirected_from_url">Redirect Page OpenRedirect</a></li>
<li><a href="/request?url=https://example.com">Request Page SSRF</a></li>
<li><a href="/email?text=important_user">Email Page SSTI</a></li>
<li><a href="/permissions?cmd=whoami">Permissions Page CMDI</a></li>
</ul>
`))
}

func infoHandler(ctx echo.Context) error {
	return ctx.HTML(200, fmt.Sprintf(bodyTemplate, fmt.Sprintf("Name of user: %s%s%s", ctx.QueryParam("name"), ctx.QueryParam("another"), ctx.QueryParam("random"))))
}

func redirectHandler(ctx echo.Context) error {
	url := ctx.QueryParam("redirect_url")
	return ctx.Redirect(302, url)
}

func requestHandler(ctx echo.Context) error {
	url := ctx.QueryParam("url")
	data, err := retryablehttp.DefaultClient().Get(url)
	if err != nil {
		return ctx.HTML(500, err.Error())
	}
	defer data.Body.Close()

	body, _ := io.ReadAll(data.Body)
	return ctx.HTML(200, fmt.Sprintf(bodyTemplate, string(body)))
}

func emailHandler(ctx echo.Context) error {
	text := ctx.QueryParam("text")
	if strings.Contains(text, "{{") {
		trimmed := strings.SplitN(strings.Trim(text[strings.Index(text, "{"):], "{}"), "*", 2)
		if len(trimmed) < 2 {
			return ctx.HTML(500, "invalid template")
		}
		first, _ := strconv.Atoi(trimmed[0])
		second, _ := strconv.Atoi(trimmed[1])
		text = strconv.Itoa(first * second)
	}
	return ctx.HTML(200, fmt.Sprintf(bodyTemplate, fmt.Sprintf("Text: %s", text)))
}

func permissionsHandler(ctx echo.Context) error {
	command := ctx.QueryParam("cmd")
	fields := strings.Fields(command)
	cmd := exec.Command(fields[0], fields[1:]...)
	data, _ := cmd.CombinedOutput()

	return ctx.HTML(200, fmt.Sprintf(bodyTemplate, string(data)))
}

func numIdorHandler(ctx echo.Context) error {
	// validate if any numerical query param is present
	// if not, return 400 if so, return 200
	for k := range ctx.QueryParams() {
		if _, err := strconv.Atoi(ctx.QueryParam(k)); err == nil {
			return ctx.JSON(200, "Profile Info for user with id "+ctx.QueryParam(k))
		}
	}
	return ctx.JSON(400, "No numerical query param found")
}

// resetPassword mock
func resetPasword(c echo.Context) error {
	var m map[string]interface{}
	if err := c.Bind(&m); err != nil {
		return c.JSON(500, "Something went wrong")
	}

	host := c.Request().Header.Get("X-Forwarded-For")
	if host == "" {
		return c.JSON(500, "Something went wrong")
	}
	resp, err := http.Get("http://internal." + host + "/update?user=1337&pass=" + m["password"].(string))
	if err != nil {
		return c.JSON(500, "Something went wrong")
	}
	defer resp.Body.Close()
	return c.JSON(200, "Password reset successfully")
}

func hostHeaderLab(c echo.Context) error {
	// vulnerable app has custom routing and trusts x-forwarded-host
	// to route to internal services
	if c.Request().Header.Get("X-Forwarded-Host") != "" {
		resp, err := http.Get("http://" + c.Request().Header.Get("X-Forwarded-Host"))
		if err != nil {
			return c.JSON(500, "Something went wrong")
		}
		defer resp.Body.Close()
		c.Response().Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		c.Response().WriteHeader(resp.StatusCode)
		_, err = io.Copy(c.Response().Writer, resp.Body)
		if err != nil {
			return c.JSON(500, "Something went wrong")
		}
	}
	return c.JSON(200, "Not a Teapot")
}
