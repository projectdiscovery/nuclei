// This package provides a mock server for testing fuzzing templates
package fuzzplayground

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"

	"github.com/projectdiscovery/retryablehttp-go"
)

// PlaygroundServer wraps the fuzz playground handler with the lifecycle methods
// used by the integration tests and the standalone playground command.
type PlaygroundServer struct {
	handler http.Handler
	server  *http.Server
}

func GetPlaygroundServer() *PlaygroundServer {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", indexHandler)
	mux.HandleFunc("GET /info", infoHandler)
	mux.HandleFunc("GET /redirect", redirectHandler)
	mux.HandleFunc("GET /request", requestHandler)
	mux.HandleFunc("GET /email", emailHandler)
	mux.HandleFunc("GET /permissions", permissionsHandler)

	mux.HandleFunc("GET /blog/post", numIdorHandler) // for num based idors like ?id=44
	mux.HandleFunc("POST /reset-password", resetPasswordHandler)
	mux.HandleFunc("GET /host-header-lab", hostHeaderLabHandler)
	mux.HandleFunc("GET /user/{id}/profile", userProfileHandler)
	mux.HandleFunc("POST /user", patchUnsanitizedUserHandler)
	mux.HandleFunc("GET /blog/posts", getPostsHandler)

	handler := recoverPlaygroundRequest(logPlaygroundRequest(mux))
	return &PlaygroundServer{handler: handler}
}

func (s *PlaygroundServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

func (s *PlaygroundServer) Start(addr string) error {
	s.server = &http.Server{
		Addr:    addr,
		Handler: s.handler,
	}
	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *PlaygroundServer) Close() error {
	if s.server == nil {
		return nil
	}
	return s.server.Close()
}

var bodyTemplate = `<html>
<head>
<title>Fuzz Playground</title>
</head>
<body>
%s
</body>
</html>`

func indexHandler(w http.ResponseWriter, _ *http.Request) {
	writeHTML(w, http.StatusOK, fmt.Sprintf(bodyTemplate, `<h1>Fuzzing Playground</h1><hr>
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

func infoHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	writeHTML(w, http.StatusOK, fmt.Sprintf(bodyTemplate, fmt.Sprintf("Name of user: %s%s%s", query.Get("name"), query.Get("another"), query.Get("random"))))
}

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("redirect_url"), http.StatusFound)
}

func requestHandler(w http.ResponseWriter, r *http.Request) {
	requestURL := r.URL.Query().Get("url")
	data, err := retryablehttp.DefaultClient().Get(requestURL)
	if err != nil {
		writeHTML(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer func() {
		_ = data.Body.Close()
	}()

	body, _ := io.ReadAll(data.Body)
	writeHTML(w, http.StatusOK, fmt.Sprintf(bodyTemplate, string(body)))
}

func emailHandler(w http.ResponseWriter, r *http.Request) {
	text := r.URL.Query().Get("text")
	if strings.Contains(text, "{{") {
		trimmed := strings.SplitN(strings.Trim(text[strings.Index(text, "{"):], "{}"), "*", 2)
		if len(trimmed) < 2 {
			writeHTML(w, http.StatusInternalServerError, "invalid template")
			return
		}
		first, _ := strconv.Atoi(trimmed[0])
		second, _ := strconv.Atoi(trimmed[1])
		text = strconv.Itoa(first * second)
	}
	writeHTML(w, http.StatusOK, fmt.Sprintf(bodyTemplate, fmt.Sprintf("Text: %s", text)))
}

func permissionsHandler(w http.ResponseWriter, r *http.Request) {
	command := r.URL.Query().Get("cmd")
	fields := strings.Fields(command)
	cmd := exec.Command(fields[0], fields[1:]...)
	data, _ := cmd.CombinedOutput()

	writeHTML(w, http.StatusOK, fmt.Sprintf(bodyTemplate, string(data)))
}

func numIdorHandler(w http.ResponseWriter, r *http.Request) {
	// validate if any numerical query param is present
	// if not, return 400 if so, return 200
	for k := range r.URL.Query() {
		value := r.URL.Query().Get(k)
		if _, err := strconv.Atoi(value); err == nil {
			writeJSON(w, http.StatusOK, "Profile Info for user with id "+value)
			return
		}
	}
	writeJSON(w, http.StatusBadRequest, "No numerical query param found")
}

func patchUnsanitizedUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User

	contentType := r.Header.Get("Content-Type")
	// manually handle unmarshalling data
	if strings.Contains(contentType, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			writeJSON(w, http.StatusInternalServerError, "Invalid JSON data")
			return
		}
	} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		user.Name = r.FormValue("name")
		user.Age, _ = strconv.Atoi(r.FormValue("age"))
		user.Role = r.FormValue("role")
		user.ID, _ = strconv.Atoi(r.FormValue("id"))
	} else if strings.Contains(contentType, "application/xml") {
		bin, _ := io.ReadAll(r.Body)
		err := xml.Unmarshal(bin, &user)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, "Invalid XML data")
			return
		}
	} else if strings.Contains(contentType, "multipart/form-data") {
		user.Name = r.FormValue("name")
		user.Age, _ = strconv.Atoi(r.FormValue("age"))
		user.Role = r.FormValue("role")
		user.ID, _ = strconv.Atoi(r.FormValue("id"))
	} else {
		writeJSON(w, http.StatusInternalServerError, "Invalid Content-Type")
		return
	}

	err := patchUnsanitizedUser(db, user)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, "User updated successfully")
}

// resetPassword mock
func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var m map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		writeJSON(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	host := r.Header.Get("X-Forwarded-For")
	if host == "" {
		writeJSON(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	password, ok := m["password"].(string)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	resp, err := http.Get("http://internal." + host + "/update?user=1337&pass=" + password)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	writeJSON(w, http.StatusOK, "Password reset successfully")
}

func hostHeaderLabHandler(w http.ResponseWriter, r *http.Request) {
	// vulnerable app has custom routing and trusts x-forwarded-host
	// to route to internal services
	if r.Header.Get("X-Forwarded-Host") != "" {
		resp, err := http.Get("http://" + r.Header.Get("X-Forwarded-Host"))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, "Something went wrong")
			return
		}
		defer func() {
			_ = resp.Body.Close()
		}()
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, err = io.Copy(w, resp.Body)
		if err != nil {
			return
		}
		return
	}
	writeJSON(w, http.StatusOK, "Not a Teapot")
}

func userProfileHandler(w http.ResponseWriter, r *http.Request) {
	val, _ := url.PathUnescape(r.PathValue("id"))
	fmt.Printf("Unescaped: %s\n", val)
	user, err := getUnsanitizedUser(db, val)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func getPostsHandler(w http.ResponseWriter, r *http.Request) {
	lang, err := r.Cookie("lang")
	if err != nil {
		// If the language cookie is missing, default to English
		lang = new(http.Cookie)
		lang.Value = "en"
	}
	posts, err := getUnsanitizedPostsByLang(db, lang.Value)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, posts)
}

func writeHTML(w http.ResponseWriter, statusCode int, value string) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(statusCode)
	_, _ = io.WriteString(w, value)
}

func writeJSON(w http.ResponseWriter, statusCode int, value interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(value)
}

func recoverPlaygroundRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func logPlaygroundRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.RequestURI())
		next.ServeHTTP(w, r)
	})
}
