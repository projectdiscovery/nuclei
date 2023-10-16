package main

import (
	"fmt"
	"io"
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
