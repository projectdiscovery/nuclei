package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"gopkg.in/yaml.v2"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	logutil "github.com/projectdiscovery/utils/log"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var httpTestcases = []TestCaseInfo{
	// TODO: excluded due to parsing errors with console
	// "http/raw-unsafe-request.yaml":                  &httpRawUnsafeRequest{},
	{Path: "http/get-headers.yaml", TestCase: &httpGetHeaders{}},
	{Path: "http/get-query-string.yaml", TestCase: &httpGetQueryString{}},
	{Path: "http/get-redirects.yaml", TestCase: &httpGetRedirects{}},
	{Path: "http/get-host-redirects.yaml", TestCase: &httpGetHostRedirects{}},
	{Path: "http/disable-redirects.yaml", TestCase: &httpDisableRedirects{}},
	{Path: "http/get.yaml", TestCase: &httpGet{}},
	{Path: "http/post-body.yaml", TestCase: &httpPostBody{}},
	{Path: "http/post-json-body.yaml", TestCase: &httpPostJSONBody{}},
	{Path: "http/post-multipart-body.yaml", TestCase: &httpPostMultipartBody{}},
	{Path: "http/raw-cookie-reuse.yaml", TestCase: &httpRawCookieReuse{}},
	{Path: "http/raw-dynamic-extractor.yaml", TestCase: &httpRawDynamicExtractor{}},
	{Path: "http/raw-get-query.yaml", TestCase: &httpRawGetQuery{}},
	{Path: "http/raw-get.yaml", TestCase: &httpRawGet{}},
	{Path: "http/raw-with-params.yaml", TestCase: &httpRawWithParams{}},
	{Path: "http/raw-unsafe-with-params.yaml", TestCase: &httpRawWithParams{}}, // Not a typo, functionality is same as above
	{Path: "http/raw-path-trailing-slash.yaml", TestCase: &httpRawPathTrailingSlash{}},
	{Path: "http/raw-payload.yaml", TestCase: &httpRawPayload{}},
	{Path: "http/raw-post-body.yaml", TestCase: &httpRawPostBody{}},
	{Path: "http/raw-unsafe-path.yaml", TestCase: &httpRawUnsafePath{}},
	{Path: "http/http-paths.yaml", TestCase: &httpPaths{}},
	{Path: "http/request-condition.yaml", TestCase: &httpRequestCondition{}},
	{Path: "http/request-condition-new.yaml", TestCase: &httpRequestCondition{}},
	{Path: "http/self-contained.yaml", TestCase: &httpRequestSelfContained{}},
	{Path: "http/self-contained-with-path.yaml", TestCase: &httpRequestSelfContained{}}, // Not a typo, functionality is same as above
	{Path: "http/self-contained-with-params.yaml", TestCase: &httpRequestSelfContainedWithParams{}},
	{Path: "http/self-contained-file-input.yaml", TestCase: &httpRequestSelfContainedFileInput{}},
	{Path: "http/get-case-insensitive.yaml", TestCase: &httpGetCaseInsensitive{}},
	{Path: "http/get.yaml,http/get-case-insensitive.yaml", TestCase: &httpGetCaseInsensitiveCluster{}},
	{Path: "http/get-redirects-chain-headers.yaml", TestCase: &httpGetRedirectsChainHeaders{}},
	{Path: "http/dsl-matcher-variable.yaml", TestCase: &httpDSLVariable{}},
	{Path: "http/dsl-functions.yaml", TestCase: &httpDSLFunctions{}},
	{Path: "http/race-simple.yaml", TestCase: &httpRaceSimple{}},
	{Path: "http/race-multiple.yaml", TestCase: &httpRaceMultiple{}},
	{Path: "http/stop-at-first-match.yaml", TestCase: &httpStopAtFirstMatch{}},
	{Path: "http/stop-at-first-match-with-extractors.yaml", TestCase: &httpStopAtFirstMatchWithExtractors{}},
	{Path: "http/variables.yaml", TestCase: &httpVariables{}},
	{Path: "http/variable-dsl-function.yaml", TestCase: &httpVariableDSLFunction{}},
	{Path: "http/get-override-sni.yaml", TestCase: &httpSniAnnotation{}},
	{Path: "http/get-sni.yaml", TestCase: &customCLISNI{}},
	{Path: "http/redirect-match-url.yaml", TestCase: &httpRedirectMatchURL{}},
	{Path: "http/get-sni-unsafe.yaml", TestCase: &customCLISNIUnsafe{}},
	{Path: "http/annotation-timeout.yaml", TestCase: &annotationTimeout{}},
	{Path: "http/custom-attack-type.yaml", TestCase: &customAttackType{}},
	{Path: "http/get-all-ips.yaml", TestCase: &scanAllIPS{}},
	{Path: "http/get-without-scheme.yaml", TestCase: &httpGetWithoutScheme{}},
	{Path: "http/cl-body-without-header.yaml", TestCase: &httpCLBodyWithoutHeader{}},
	{Path: "http/cl-body-with-header.yaml", TestCase: &httpCLBodyWithHeader{}},
	{Path: "http/save-extractor-values-to-file.yaml", TestCase: &httpSaveExtractorValuesToFile{}},
	{Path: "http/cli-with-constants.yaml", TestCase: &ConstantWithCliVar{}},
	{Path: "http/matcher-status.yaml", TestCase: &matcherStatusTest{}},
	{Path: "http/disable-path-automerge.yaml", TestCase: &httpDisablePathAutomerge{}},
}

type httpInteractshRequest struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpInteractshRequest) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		value := r.Header.Get("url")
		if value != "" {
			if resp, _ := retryablehttp.DefaultClient().Get(value); resp != nil {
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

type httpDefaultMatcherCondition struct{}

// Execute executes a test case and returns an error if occurred
func (d *httpDefaultMatcherCondition) Execute(filePath string) error {
	// to simulate matcher-condition `or`
	// - template should be run twice and vulnerable server should send response that fits for that specific run
	router := httprouter.New()
	var routerErr error
	// Server endpoint where only interactsh matcher is successful and status code is not 200
	router.GET("/interactsh/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		value := r.URL.Query().Get("url")
		if value != "" {
			if _, err := retryablehttp.DefaultClient().Get("https://" + value); err != nil {
				routerErr = err
			}
		}
		w.WriteHeader(http.StatusNotFound)
	})
	// Server endpoint where url is not probed but sends a 200 status code
	router.GET("/status/", func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL+"/status", debug)
	if err != nil {
		return err
	}
	if err := expectResultsCount(results, 1); err != nil {
		return err
	}

	results, err = testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL+"/interactsh", debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return errorutil.NewWithErr(routerErr).Msgf("failed to send http request to interactsh server")
	}
	if err := expectResultsCount(results, 1); err != nil {
		return err
	}
	return nil
}

type httpInteractshStopAtFirstMatchRequest struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpInteractshStopAtFirstMatchRequest) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		value := r.Header.Get("url")
		if value != "" {
			if resp, _ := retryablehttp.DefaultClient().Get(value); resp != nil {
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
	// polling is asynchronous, so the interactions may be retrieved after the first request
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

type httpGetHostRedirects struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpGetHostRedirects) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		http.Redirect(w, r, "/redirected1", http.StatusFound)
	})
	router.GET("/redirected1", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		http.Redirect(w, r, "redirected2", http.StatusFound)
	})
	router.GET("/redirected2", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		http.Redirect(w, r, "/redirected3", http.StatusFound)
	})
	router.GET("/redirected3", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		http.Redirect(w, r, "https://scanme.sh", http.StatusTemporaryRedirect)
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type httpDisableRedirects struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpDisableRedirects) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		http.Redirect(w, r, "/redirected", http.StatusMovedPermanently)
	})
	router.GET("/redirected", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "This is test redirects matcher text")
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-dr")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 0)
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

	// get result part
	resultPart, err := stringsutil.After(results[0], ts.URL)
	if err != nil {
		return err
	}

	// remove additional characters till the first valid result and ignore last ] which doesn't alter the total count
	resultPart = stringsutil.TrimPrefixAny(resultPart, "/", " ", "[")

	extracted := strings.Split(resultPart, ",")
	numberOfDslFunctions := 88
	if len(extracted) != numberOfDslFunctions {
		return errors.New("incorrect number of results")
	}

	for _, header := range extracted {
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

	return expectResultsCount(results, 1)
}

type httpRawGet struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpRawGet) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "Test is test raw-get-matcher text")
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type httpRawWithParams struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpRawWithParams) Execute(filePath string) error {
	router := httprouter.New()
	var errx error
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		params := r.URL.Query()
		// we intentionally use params["test"] instead of params.Get("test") to test the case where
		// there are multiple parameters with the same name
		if !reflect.DeepEqual(params["key1"], []string{"value1"}) {
			errx = errorutil.WrapfWithNil(errx, "expected %v, got %v", []string{"value1"}, params["key1"])
		}
		if !reflect.DeepEqual(params["key2"], []string{"value2"}) {
			errx = errorutil.WrapfWithNil(errx, "expected %v, got %v", []string{"value2"}, params["key2"])
		}
		fmt.Fprintf(w, "Test is test raw-params-matcher text")
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL+"/?key1=value1", debug)
	if err != nil {
		return err
	}
	if errx != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type httpRawPathTrailingSlash struct{}

func (h *httpRawPathTrailingSlash) Execute(filepath string) error {
	router := httprouter.New()
	var routerErr error

	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if r.RequestURI != "/test/..;/..;/" {
			routerErr = fmt.Errorf("expected path /test/..;/..;/ but got %v", r.RequestURI)
			return
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	_, err := testutils.RunNucleiTemplateAndGetResults(filepath, ts.URL, debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}
	return nil
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

type httpRawUnsafePath struct{}

func (h *httpRawUnsafePath) Execute(filepath string) error {
	// testing unsafe paths using router feedback is not possible cause they are `unsafe urls`
	// hence it is done by parsing and matching paths from nuclei output with `-debug-req` flag
	// read template files
	bin, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}

	// Instead of storing expected `paths` in code it is stored in
	// `reference` section of template
	type template struct {
		Info struct {
			Reference []string `yaml:"reference"`
		}
	}
	var tpl template
	if err = yaml.Unmarshal(bin, &tpl); err != nil {
		return err
	}
	// expected relative paths
	expected := []string{}
	expected = append(expected, tpl.Info.Reference...)
	if len(expected) == 0 {
		return fmt.Errorf("something went wrong with %v template", filepath)
	}

	results, err := testutils.RunNucleiBinaryAndGetCombinedOutput(debug, []string{"-t", filepath, "-u", "scanme.sh", "-debug-req"})
	if err != nil {
		return err
	}

	actual := []string{}
	for _, v := range strings.Split(results, "\n") {
		if strings.Contains(v, "GET") {
			parts := strings.Fields(v)
			if len(parts) == 3 {
				actual = append(actual, parts[1])
			}
		}
	}

	if !reflect.DeepEqual(expected, actual) {
		return fmt.Errorf("%8v: %v\n%-8v: %v", "expected", expected, "actual", actual)
	}
	return nil
}

type httpPaths struct{}

func (h *httpPaths) Execute(filepath string) error {
	// covers testcases similar to httpRawUnsafePath but when `unsafe:false`
	bin, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}

	// Instead of storing expected `paths` in code it is stored in
	// `reference` section of template
	type template struct {
		Info struct {
			Reference []string `yaml:"reference"`
		}
	}
	var tpl template
	if err = yaml.Unmarshal(bin, &tpl); err != nil {
		return err
	}
	// expected relative paths
	expected := []string{}
	expected = append(expected, tpl.Info.Reference...)
	if len(expected) == 0 {
		return fmt.Errorf("something went wrong with %v template", filepath)
	}

	results, err := testutils.RunNucleiBinaryAndGetCombinedOutput(debug, []string{"-t", filepath, "-u", "scanme.sh", "-debug-req"})
	if err != nil {
		return err
	}

	actual := []string{}
	for _, v := range strings.Split(results, "\n") {
		if strings.Contains(v, "GET") {
			parts := strings.Fields(v)
			if len(parts) == 3 {
				actual = append(actual, parts[1])
			}
		}
	}

	if !reflect.DeepEqual(expected, actual) {
		return fmt.Errorf("%8v: %v\n%-8v: %v", "expected", expected, "actual", actual)
	}
	return nil
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

// TODO: excluded due to parsing errors with console
// type httpRawUnsafeRequest struct{
// Execute executes a test case and returns an error if occurred
// func (h *httpRawUnsafeRequest) Execute(filePath string) error {
// 	var routerErr error
//
// 	ts := testutils.NewTCPServer(nil, defaultStaticPort, func(conn net.Conn) {
// 		defer conn.Close()
// 		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 36\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nThis is test raw-unsafe-matcher test"))
// 	})
// 	defer ts.Close()
//
// 	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "http://"+ts.URL, debug)
// 	if err != nil {
// 		return err
// 	}
// 	if routerErr != nil {
// 		return routerErr
// 	}
//
// 	return expectResultsCount(results, 1)
// }

type httpRequestCondition struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpRequestCondition) Execute(filePath string) error {
	router := httprouter.New()

	router.GET("/200", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.WriteHeader(http.StatusOK)
	})
	router.GET("/400", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.WriteHeader(http.StatusBadRequest)
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type httpRequestSelfContained struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpRequestSelfContained) Execute(filePath string) error {
	router := httprouter.New()
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

	return expectResultsCount(results, 1)
}

// testcase to check duplicated values in params
type httpRequestSelfContainedWithParams struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpRequestSelfContainedWithParams) Execute(filePath string) error {
	router := httprouter.New()
	var errx error
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		params := r.URL.Query()
		// we intentionally use params["test"] instead of params.Get("test") to test the case where
		// there are multiple parameters with the same name
		if !reflect.DeepEqual(params["something"], []string{"here"}) {
			errx = errorutil.WrapfWithNil(errx, "expected %v, got %v", []string{"here"}, params["something"])
		}
		if !reflect.DeepEqual(params["key"], []string{"value"}) {
			errx = errorutil.WrapfWithNil(errx, "expected %v, got %v", []string{"value"}, params["key"])
		}
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
	if errx != nil {
		return errx
	}

	return expectResultsCount(results, 1)
}

type httpRequestSelfContainedFileInput struct{}

func (h *httpRequestSelfContainedFileInput) Execute(filePath string) error {
	router := httprouter.New()
	gotReqToEndpoints := []string{}
	router.GET("/one", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		gotReqToEndpoints = append(gotReqToEndpoints, "/one")
		_, _ = w.Write([]byte("This is self-contained response"))
	})
	router.GET("/two", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		gotReqToEndpoints = append(gotReqToEndpoints, "/two")
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

	// create temp file
	FileLoc, err := os.CreateTemp("", "self-contained-payload-*.txt")
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("failed to create temp file")
	}
	if _, err := FileLoc.Write([]byte("one\ntwo\n")); err != nil {
		return errorutil.NewWithErr(err).Msgf("failed to write payload to temp file")
	}
	defer FileLoc.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "", debug, "-V", "test="+FileLoc.Name())
	if err != nil {
		return err
	}

	if err := expectResultsCount(results, 4); err != nil {
		return err
	}

	if !sliceutil.ElementsMatch(gotReqToEndpoints, []string{"/one", "/two", "/one", "/two"}) {
		return errorutil.NewWithTag(filePath, "expected requests to be sent to `/one` and `/two` endpoints but were sent to `%v`", gotReqToEndpoints)
	}
	return nil
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

type httpVariables struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpVariables) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "%s\n%s\n%s", r.Header.Get("Test"), r.Header.Get("Another"), r.Header.Get("Email"))
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	if err := expectResultsCount(results, 1); err != nil {
		return err
	}

	// variable override that does not have any match
	// to make sure the variable override is working
	results, err = testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-var", "a1=failed")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 0)
}

type httpVariableDSLFunction struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpVariableDSLFunction) Execute(filePath string) error {
	results, err := testutils.RunNucleiBinaryAndGetCombinedOutput(debug, []string{"-t", filePath, "-u", "https://scanme.sh", "-debug-req"})
	if err != nil {
		return err
	}

	actual := []string{}
	for _, v := range strings.Split(results, "\n") {
		if strings.Contains(v, "GET") {
			parts := strings.Fields(v)
			if len(parts) == 3 {
				actual = append(actual, parts[1])
			}
		}
	}
	if len(actual) == 2 && actual[0] == actual[1] {
		return nil
	}

	return fmt.Errorf("expected 2 requests with same URL, got %v", actual)
}

type customCLISNI struct{}

// Execute executes a test case and returns an error if occurred
func (h *customCLISNI) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if r.TLS.ServerName == "test" {
			_, _ = w.Write([]byte("test-ok"))
		} else {
			_, _ = w.Write([]byte("test-ko"))
		}
	})
	ts := httptest.NewTLSServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-sni", "test")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type httpSniAnnotation struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpSniAnnotation) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if r.TLS.ServerName == "test" {
			_, _ = w.Write([]byte("test-ok"))
		} else {
			_, _ = w.Write([]byte("test-ko"))
		}
	})
	ts := httptest.NewTLSServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type httpRedirectMatchURL struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpRedirectMatchURL) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		http.Redirect(w, r, "/redirected", http.StatusFound)
		_, _ = w.Write([]byte("This is test redirects matcher text"))
	})
	router.GET("/redirected", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "This is test redirects matcher text")
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-no-meta")
	if err != nil {
		return err
	}

	if err := expectResultsCount(results, 1); err != nil {
		return err
	}
	if results[0] != fmt.Sprintf("%s/redirected", ts.URL) {
		return fmt.Errorf("mismatched url found: %s", results[0])
	}
	return nil
}

type customCLISNIUnsafe struct{}

// Execute executes a test case and returns an error if occurred
func (h *customCLISNIUnsafe) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if r.TLS.ServerName == "test" {
			_, _ = w.Write([]byte("test-ok"))
		} else {
			_, _ = w.Write([]byte("test-ko"))
		}
	})
	ts := httptest.NewTLSServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-sni", "test")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type annotationTimeout struct{}

// Execute executes a test case and returns an error if occurred
func (h *annotationTimeout) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		time.Sleep(4 * time.Second)
		fmt.Fprintf(w, "This is test matcher text")
	})
	ts := httptest.NewTLSServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-timeout", "1")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

type customAttackType struct{}

// Execute executes a test case and returns an error if occurred
func (h *customAttackType) Execute(filePath string) error {
	router := httprouter.New()
	got := []string{}
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		got = append(got, r.URL.RawQuery)
		fmt.Fprintf(w, "This is test custom payload")
	})
	ts := httptest.NewTLSServer(router)
	defer ts.Close()

	_, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-attack-type", "clusterbomb")
	if err != nil {
		return err
	}
	return expectResultsCount(got, 4)
}

// Disabled as GH doesn't support ipv6
type scanAllIPS struct{}

// Execute executes a test case and returns an error if occurred
func (h *scanAllIPS) Execute(filePath string) error {
	got, err := testutils.RunNucleiTemplateAndGetResults(filePath, "https://scanme.sh", debug, "-scan-all-ips", "-iv", "4")
	if err != nil {
		return err
	}
	// limiting test to ipv4 (GH doesn't support ipv6)
	return expectResultsCount(got, 1)
}

// ensure that ip|host are handled without http|https scheme
type httpGetWithoutScheme struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpGetWithoutScheme) Execute(filePath string) error {
	got, err := testutils.RunNucleiTemplateAndGetResults(filePath, "scanme.sh", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(got, 1)
}

// content-length in case the response has no header but has a body
type httpCLBodyWithoutHeader struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpCLBodyWithoutHeader) Execute(filePath string) error {
	logutil.DisableDefaultLogger()
	defer logutil.EnableDefaultLogger()

	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.Header()["Content-Length"] = []string{"-1"}
		fmt.Fprintf(w, "this is a test")
	})
	ts := httptest.NewTLSServer(router)
	defer ts.Close()

	got, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	return expectResultsCount(got, 1)
}

// content-length in case the response has content-length header and a body
type httpCLBodyWithHeader struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpCLBodyWithHeader) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.Header()["Content-Length"] = []string{"50000"}
		fmt.Fprintf(w, "this is a test")
	})
	ts := httptest.NewTLSServer(router)
	defer ts.Close()

	got, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	return expectResultsCount(got, 1)
}

type httpSaveExtractorValuesToFile struct{}

func (h *httpSaveExtractorValuesToFile) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		var buff bytes.Buffer
		for i := 0; i < 10; i++ {
			buff.WriteString(fmt.Sprintf(`"value": %v`+"\n", i))
		}
		_, _ = w.Write(buff.Bytes())
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}

	// remove output.txt file if exists
	if !fileutil.FileExists("output.txt") {
		return fmt.Errorf("extractor output file output.txt file does not exist")
	} else {
		_ = os.Remove("output.txt")
	}
	return expectResultsCount(results, 1)
}

// constant shouldn't be overwritten by cli var with same name
type ConstantWithCliVar struct{}

// Execute executes a test case and returns an error if occurred
func (h *ConstantWithCliVar) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprint(w, r.URL.Query().Get("p"))
	})
	ts := httptest.NewTLSServer(router)
	defer ts.Close()

	got, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-V", "test=fromcli")
	if err != nil {
		return err
	}
	return expectResultsCount(got, 1)
}

type matcherStatusTest struct{}

// Execute executes a test case and returns an error if occurred
func (h *matcherStatusTest) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/200", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-ms")
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

// disable path automerge in raw request
type httpDisablePathAutomerge struct{}

// Execute executes a test case and returns an error if occurred
func (h *httpDisablePathAutomerge) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/api/v1/test", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprint(w, r.URL.Query().Get("id"))
	})
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprint(w, "empty path in raw request")
	})

	ts := httptest.NewServer(router)
	defer ts.Close()
	got, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL+"/api/v1/user", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(got, 2)
}

type httpInteractshRequestsWithMCAnd struct{}

func (h *httpInteractshRequestsWithMCAnd) Execute(filePath string) error {
	got, err := testutils.RunNucleiTemplateAndGetResults(filePath, "honey.scanme.sh", debug)
	if err != nil {
		return err
	}
	return expectResultsCount(got, 1)
}
