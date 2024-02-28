package main

import (
	"database/sql"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	_ "github.com/mattn/go-sqlite3"
	"github.com/projectdiscovery/retryablehttp-go"
)

var (
	db        *sql.DB
	tempDBDir string
)

func init() {
	dir, err := os.MkdirTemp("", "fuzzplayground-*")
	if err != nil {
		panic(err)
	}
	tempDBDir = dir

	db, err = sql.Open("sqlite3", fmt.Sprintf("file:%v/test.db?cache=shared&mode=memory", tempDBDir))
	if err != nil {
		panic(err)
	}
	addDummyUsers(db)
	addDummyPosts(db)
}

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
	e.GET("/user/:id/profile", userProfile)
	e.POST("/user", patchUnsanitizedUserHandler)
	e.GET("/blog/posts", getPostsHandler)
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

func userProfile(ctx echo.Context) error {
	val, _ := url.PathUnescape(ctx.Param("id"))
	fmt.Printf("Unescaped: %s\n", val)
	user, err := getUnsanitizedUser(db, val)
	if err != nil {
		return ctx.JSON(500, err.Error())
	}
	return ctx.JSON(200, user)
}

type User struct {
	ID   int
	Name string
	Age  int
	Role string
}

func addDummyUsers(db *sql.DB) {
	_, err := db.Exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, age INTEGER, role TEXT)")
	if err != nil {
		panic(err)
	}
	_, err = db.Exec("INSERT INTO users (id , name, age, role) VALUES (1,'admin', 30, 'admin')")
	if err != nil {
		panic(err)
	}
	_, err = db.Exec("INSERT INTO users (id , name, age, role) VALUES (75,'user', 30, 'user')")
	if err != nil {
		panic(err)
	}
}

func patchUnsanitizedUser(db *sql.DB, user User) error {
	setClauses := ""

	if user.Name != "" {
		setClauses += "name = '" + user.Name + "', "
	}
	if user.Age > 0 {
		setClauses += "age = " + strconv.Itoa(user.Age) + ", "
	}
	if user.Role != "" {
		setClauses += "role = '" + user.Role + "', "
	}
	if setClauses == "" {
		// No fields to update
		return nil
	}
	setClauses = strings.TrimSuffix(setClauses, ", ")

	query := "UPDATE users SET " + setClauses + " WHERE id = ?"
	_, err := db.Exec(query, user.ID)
	if err != nil {
		return err
	}
	return nil
}

func getUnsanitizedUser(db *sql.DB, id string) (User, error) {
	var user User
	err := db.QueryRow("SELECT id, name, age, role FROM users WHERE id = "+id).Scan(&user.ID, &user.Name, &user.Age, &user.Role)
	if err != nil {
		return user, err
	}
	return user, nil
}

type Posts struct {
	ID      int
	Title   string
	Content string
	Lang    string
}

func addDummyPosts(db *sql.DB) {
	_, err := db.Exec("CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY, title TEXT, content TEXT, lang TEXT)")
	if err != nil {
		panic(err)
	}
	// Inserting English dummy posts
	_, err = db.Exec("INSERT INTO posts (id, title, content, lang) VALUES (1, 'The Joy of Programming', 'Programming is like painting a canvas with logic.', 'en')")
	if err != nil {
		panic(err)
	}
	_, err = db.Exec("INSERT INTO posts (id, title, content, lang) VALUES (2, 'A Journey Through Code', 'Every line of code tells a story.', 'en')")
	if err != nil {
		panic(err)
	}
	// Inserting a Spanish dummy post
	_, err = db.Exec("INSERT INTO posts (id, title, content, lang) VALUES (3, 'La belleza del código', 'Cada función es un poema en un mar de algoritmos.', 'es')")
	if err != nil {
		panic(err)
	}
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
func getUnsanitizedPostsByLang(db *sql.DB, lang string) ([]Posts, error) {
	var posts []Posts
	query := "SELECT id, title, content, lang FROM posts WHERE lang = '" + lang + "'"
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var post Posts
		if err := rows.Scan(&post.ID, &post.Title, &post.Content, &post.Lang); err != nil {
			return nil, err
		}
		posts = append(posts, post)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return posts, nil
}
