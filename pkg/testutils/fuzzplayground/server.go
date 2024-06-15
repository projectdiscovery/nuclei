// This package provides a mock server for testing fuzzing templates
package fuzzplayground

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/projectdiscovery/retryablehttp-go"
)

func GetPlaygroundServer() *echo.Echo {
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
	e.POST("/reset-password", resetPasswordHandler)
	e.GET("/host-header-lab", hostHeaderLabHandler)
	e.GET("/user/:id/profile", userProfileHandler)
	e.POST("/user", patchUnsanitizedUserHandler)
	e.GET("/blog/posts", getPostsHandler)
	return e
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
	
	<li><a href="/host-header-lab">Host Header Lab (X-Forwarded-Host Trusted)</a></li>
	<li><a href="/user/75/profile">User Profile Page SQLI (path parameter)</a></li>
	<li><a href="/user">POST on /user SQLI (body parameter)</a></li>
	<li><a href="/blog/posts">SQLI in cookie lang parameter value (eg. lang=en)</a></li>
	
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

func patchUnsanitizedUserHandler(ctx echo.Context) error {
	var user User

	contentType := ctx.Request().Header.Get("Content-Type")
	// manually handle unmarshalling data
	if strings.Contains(contentType, "application/json") {
		err := ctx.Bind(&user)
		if err != nil {
			return ctx.JSON(500, "Invalid JSON data")
		}
	} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		user.Name = ctx.FormValue("name")
		user.Age, _ = strconv.Atoi(ctx.FormValue("age"))
		user.Role = ctx.FormValue("role")
		user.ID, _ = strconv.Atoi(ctx.FormValue("id"))
	} else if strings.Contains(contentType, "application/xml") {
		bin, _ := io.ReadAll(ctx.Request().Body)
		err := xml.Unmarshal(bin, &user)
		if err != nil {
			return ctx.JSON(500, "Invalid XML data")
		}
	} else if strings.Contains(contentType, "multipart/form-data") {
		user.Name = ctx.FormValue("name")
		user.Age, _ = strconv.Atoi(ctx.FormValue("age"))
		user.Role = ctx.FormValue("role")
		user.ID, _ = strconv.Atoi(ctx.FormValue("id"))
	} else {
		return ctx.JSON(500, "Invalid Content-Type")
	}

	err := patchUnsanitizedUser(db, user)
	if err != nil {
		return ctx.JSON(500, err.Error())
	}
	return ctx.JSON(200, "User updated successfully")
}

// resetPassword mock
func resetPasswordHandler(c echo.Context) error {
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

func hostHeaderLabHandler(c echo.Context) error {
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

func userProfileHandler(ctx echo.Context) error {
	val, _ := url.PathUnescape(ctx.Param("id"))
	fmt.Printf("Unescaped: %s\n", val)
	user, err := getUnsanitizedUser(db, val)
	if err != nil {
		return ctx.JSON(500, err.Error())
	}
	return ctx.JSON(200, user)
}

func getPostsHandler(c echo.Context) error {
	lang, err := c.Cookie("lang")
	if err != nil {
		// If the language cookie is missing, default to English
		lang = new(http.Cookie)
		lang.Value = "en"
	}
	posts, err := getUnsanitizedPostsByLang(db, lang.Value)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, posts)
}
