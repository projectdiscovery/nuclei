package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"regexp"
	"strconv"
	"strings"

	"github.com/julienschmidt/httprouter"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var httpTestcases = map[string]testutils.TestCase{
	"http/get-headers.yaml":                         &httpGetHeaders{},
	"http/get-query-string.yaml":                    &httpGetQueryString{},
	"http/get-redirects.yaml":                       &httpGetRedirects{},
	"http/get.yaml":                                 &httpGet{},
	"http/post-body.yaml":                           &httpPostBody{},
	"http/post-json-body.yaml":                      &httpPostJSONBody{},
	"http/post-multipart-body.yaml":                 &httpPostMultipartBody{},
	"http/raw-cookie-reuse.yaml":                    &httpRawCookieReuse{},
	"http/raw-dynamic-extractor.yaml":               &httpRawDynamicExtractor{},
	"http/raw-get-query.yaml":                       &httpRawGetQuery{},
	"http/raw-get.yaml":                             &httpRawGet{},
	"http/raw-payload.yaml":                         &httpRawPayload{},
	"http/raw-post-body.yaml":                       &httpRawPostBody{},
	"http/raw-unsafe-request.yaml":                  &httpRawUnsafeRequest{},
	"http/request-condition.yaml":                   &httpRequestCondition{},
	"http/request-condition-new.yaml":               &httpRequestCondition{},
	"http/interactsh.yaml":                          &httpInteractshRequest{},
	"http/interactsh-stop-at-first-match.yaml":      &httpInteractshStopAtFirstMatchRequest{},
	"http/self-contained.yaml":                      &httpRequestSelContained{},
	"http/get-case-insensitive.yaml":                &httpGetCaseInsensitive{},
	"http/get.yaml,http/get-case-insensitive.yaml":  &httpGetCaseInsensitiveCluster{},
	"http/get-redirects-chain-headers.yaml":         &httpGetRedirectsChainHeaders{},
	"http/dsl-matcher-variable.yaml":                &httpDSLVariable{},
	"http/dsl-functions.yaml":                       &httpDSLFunctions{},
	"http/race-simple.yaml":                         &httpRaceSimple{},
	"http/race-multiple.yaml":                       &httpRaceMultiple{},
	"http/stop-at-first-match.yaml":                 &httpStopAtFirstMatch{},
	"http/stop-at-first-match-with-extractors.yaml": &httpStopAtFirstMatchWithExtractors{},
}

type httpInteractshRequest struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpInteractshRequest) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		value := r.Header.Get("url")
		if value != "" {
			if resp, _ := http.DefaultClient.Get(value); resp != nil {
				resp.Body.Close()
			}
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type httpInteractshStopAtFirstMatchRequest struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpInteractshStopAtFirstMatchRequest) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		value := r.Header.Get("url")
		if value != "" {
			if resp, _ := http.DefaultClient.Get(value); resp != nil {
				resp.Body.Close()
			}
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type httpGetHeaders struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpGetHeaders) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if strings.EqualFold(r.Header.Get("test"), "nuclei") {
			fmt.Fprintf(w, "This is test headers matcher text")
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type httpGetQueryString struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpGetQueryString) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if strings.EqualFold(r.URL.Query().Get("test"), "nuclei") {
			fmt.Fprintf(w, "This is test querystring matcher text")
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type httpGetRedirects struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpGetRedirects) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		http.Redirect(w, r, "/redirected", http.StatusFound)
	})
	router.GET("/redirected", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "This is test redirects matcher text")
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type httpGet struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpGet) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "This is test matcher text")
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type httpDSLVariable struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpDSLVariable) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "This is test matcher text")
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 5)
}

type httpDSLFunctions struct{}

func (h *httpDSLFunctions) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		request, err := httputil.DumpRequest(r, true)
		if err != nil {
			_, _ = fmt.Fprint(w, err.Error())
		} else {
			_, _ = fmt.Fprint(w, string(request))
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-nc")
	if err != nil {
		return err
	}

	if err := expectResultsCount(results, 1); err != nil {
		return err
	}

	resultPattern := regexp.MustCompile(`\[[^]]+] \[[^]]+] \[[^]]+] [^]]+ \[([^]]+)]`)
	submatch := resultPattern.FindStringSubmatch(results[0])
	if len(submatch) != 2 {
		return errors.New("could not parse the result")
	}

	totalExtracted := strings.Split(submatch[1], ",")
	numberOfDslFunctions := 54
	if len(totalExtracted) != numberOfDslFunctions {
		return errors.New("incorrect number of results")
	}

	for _, header := range totalExtracted {
		parts := strings.Split(header, ": ")
		index, err := strconv.Atoi(parts[0])
		if err != nil {
			return err
		}
		if index < 0 || index > numberOfDslFunctions {
			return fmt.Errorf("incorrect header index found: %d", index)
		}
		if strings.TrimSpace(parts[1]) == "" {
			return fmt.Errorf("the DSL expression with index %d was not evaluated correctly", index)
		}
	}

	return nil
}

type httpPostBody struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpPostBody) Execute(filePath string) error {
	router := httprouter.New()
	var routerErr error

	router.POST("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if err := r.ParseForm(); err != nil {
			routerErr = err
			return
		}
		if strings.EqualFold(r.Form.Get("username"), "test") && strings.EqualFold(r.Form.Get("password"), "nuclei") {
			fmt.Fprintf(w, "This is test post-body matcher text")
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}

	return expectResultsCount(results, 1)
}

type httpPostJSONBody struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpPostJSONBody) Execute(filePath string) error {
	router := httprouter.New()
	var routerErr error

	router.POST("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		type doc struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		obj := &doc{}
		if err := json.NewDecoder(r.Body).Decode(obj); err != nil {
			routerErr = err
			return
		}
		if strings.EqualFold(obj.Username, "test") && strings.EqualFold(obj.Password, "nuclei") {
			fmt.Fprintf(w, "This is test post-json-body matcher text")
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}

	return expectResultsCount(results, 1)
}

type httpPostMultipartBody struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpPostMultipartBody) Execute(filePath string) error {
	router := httprouter.New()
	var routerErr error

	router.POST("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if err := r.ParseMultipartForm(1 * 1024); err != nil {
			routerErr = err
			return
		}
		password, ok := r.MultipartForm.Value["password"]
		if !ok || len(password) != 1 {
			routerErr = errors.New("no password in request")
			return
		}
		file := r.MultipartForm.File["username"]
		if len(file) != 1 {
			routerErr = errors.New("no file in request")
			return
		}
		if strings.EqualFold(password[0], "nuclei") && strings.EqualFold(file[0].Filename, "username") {
			fmt.Fprintf(w, "This is test post-multipart matcher text")
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}

	return expectResultsCount(results, 1)
}

type httpRawDynamicExtractor struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpRawDynamicExtractor) Execute(filePath string) error {
	router := httprouter.New()
	var routerErr error

	router.POST("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if err := r.ParseForm(); err != nil {
			routerErr = err
			return
		}
		if strings.EqualFold(r.Form.Get("testing"), "parameter") {
			fmt.Fprintf(w, "Token: 'nuclei'")
		}
	})
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if strings.EqualFold(r.URL.Query().Get("username"), "nuclei") {
			fmt.Fprintf(w, "Test is test-dynamic-extractor-raw matcher text")
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}

	return expectResultsCount(results, 1)
}

type httpRawGetQuery struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpRawGetQuery) Execute(filePath string) error {
	router := httprouter.New()
	var routerErr error

	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if strings.EqualFold(r.URL.Query().Get("test"), "nuclei") {
			fmt.Fprintf(w, "Test is test raw-get-query-matcher text")
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}

	return expectResultsCount(results, 1)
}

type httpRawGet struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpRawGet) Execute(filePath string) error {
	router := httprouter.New()
	var routerErr error

	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "Test is test raw-get-matcher text")
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}

	return expectResultsCount(results, 1)
}

type httpRawPayload struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpRawPayload) Execute(filePath string) error {
	router := httprouter.New()
	var routerErr error

	router.POST("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if err := r.ParseForm(); err != nil {
			routerErr = err
			return
		}
		if !(strings.EqualFold(r.Header.Get("another_header"), "bnVjbGVp") || strings.EqualFold(r.Header.Get("another_header"), "Z3Vlc3Q=")) {
			return
		}
		if strings.EqualFold(r.Form.Get("username"), "test") && (strings.EqualFold(r.Form.Get("password"), "nuclei") || strings.EqualFold(r.Form.Get("password"), "guest")) {
			fmt.Fprintf(w, "Test is raw-payload matcher text")
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}

	return expectResultsCount(results, 2)
}

type httpRawPostBody struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpRawPostBody) Execute(filePath string) error {
	router := httprouter.New()
	var routerErr error

	router.POST("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if err := r.ParseForm(); err != nil {
			routerErr = err
			return
		}
		if strings.EqualFold(r.Form.Get("username"), "test") && strings.EqualFold(r.Form.Get("password"), "nuclei") {
			fmt.Fprintf(w, "Test is test raw-post-body-matcher text")
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}

	return expectResultsCount(results, 1)
}

type httpRawCookieReuse struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpRawCookieReuse) Execute(filePath string) error {
	router := httprouter.New()
	var routerErr error

	router.POST("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if err := r.ParseForm(); err != nil {
			routerErr = err
			return
		}
		if strings.EqualFold(r.Form.Get("testing"), "parameter") {
			http.SetCookie(w, &http.Cookie{Name: "nuclei", Value: "test"})
		}
	})
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if err := r.ParseForm(); err != nil {
			routerErr = err
			return
		}
		cookie, err := r.Cookie("nuclei")
		if err != nil {
			routerErr = err
			return
		}

		if strings.EqualFold(cookie.Value, "test") {
			fmt.Fprintf(w, "Test is test-cookie-reuse matcher text")
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}

	return expectResultsCount(results, 1)
}

type httpRawUnsafeRequest struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpRawUnsafeRequest) Execute(filePath string) error {
	var routerErr error

	ts := testutils.NewTCPServer(false, defaultStaticPort, func(conn net.Conn) {
		defer conn.Close()
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 36\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nThis is test raw-unsafe-matcher test"))
	})
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "http://"+ts.URL, debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}

	return expectResultsCount(results, 1)
}

type httpRequestCondition struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpRequestCondition) Execute(filePath string) error {
	router := httprouter.New()
	var routerErr error

	router.GET("/200", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.WriteHeader(200)
	})
	router.GET("/400", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.WriteHeader(400)
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}

	return expectResultsCount(results, 1)
}

type httpRequestSelContained struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpRequestSelContained) Execute(filePath string) error {
	router := httprouter.New()
	var routerErr error

	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		_, _ = w.Write([]byte("This is self-contained response"))
	})
	server := &http.Server{
		Addr:    fmt.Sprintf("localhost:%d", defaultStaticPort),
		Handler: router,
	}
	go func() {
		_ = server.ListenAndServe()
	}()
	defer server.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "", debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}

	return expectResultsCount(results, 1)
}

type httpGetCaseInsensitive struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpGetCaseInsensitive) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "THIS IS TEST MATCHER TEXT")
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type httpGetCaseInsensitiveCluster struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpGetCaseInsensitiveCluster) Execute(filesPath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "This is test matcher text")
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	files := strings.Split(filesPath, ",")

	results, err := testutils.RunNucleiTemplateAndGetResults(files[0], ts.URL, debug, "-t", files[1])
	if err != nil {
		return err
	}

	return expectResultsCount(results, 2)
}

type httpGetRedirectsChainHeaders struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpGetRedirectsChainHeaders) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		http.Redirect(w, r, "/redirected", http.StatusFound)
	})
	router.GET("/redirected", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.Header().Set("Secret", "TestRedirectHeaderMatch")
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	router.GET("/final", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		_, _ = w.Write([]byte("ok"))
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type httpRaceSimple struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpRaceSimple) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 10)
}

type httpRaceMultiple struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpRaceMultiple) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 5)
}

type httpStopAtFirstMatch struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpStopAtFirstMatch) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "This is test")
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type httpStopAtFirstMatchWithExtractors struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpStopAtFirstMatchWithExtractors) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "This is test")
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 2)
}
