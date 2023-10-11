package main

import (
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/julienschmidt/httprouter"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var headlessTestcases = []TestCaseInfo{
	{Path: "headless/headless-basic.yaml", TestCase: &headlessBasic{}},
	{Path: "headless/headless-header-action.yaml", TestCase: &headlessHeaderActions{}},
	{Path: "headless/headless-extract-values.yaml", TestCase: &headlessExtractValues{}},
	{Path: "headless/headless-payloads.yaml", TestCase: &headlessPayloads{}},
	{Path: "headless/variables.yaml", TestCase: &headlessVariables{}},
	{Path: "headless/headless-local.yaml", TestCase: &headlessLocal{}},
	{Path: "headless/file-upload.yaml", TestCase: &headlessFileUpload{}},
	{Path: "headless/file-upload-negative.yaml", TestCase: &headlessFileUploadNegative{}},
	{Path: "headless/headless-header-status-test.yaml", TestCase: &headlessHeaderStatus{}},
}

type headlessBasic struct{}

// Execute executes a test case and returns an error if occurred
func (h *headlessBasic) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		_, _ = w.Write([]byte("<html><body></body></html>"))
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-headless")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type headlessLocal struct{}

// Execute executes a test case and returns an error if occurred
// in this testcases local network access is disabled
func (h *headlessLocal) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		_, _ = w.Write([]byte("<html><body></body></html>"))
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	args := []string{"-t", filePath, "-u", ts.URL, "-headless", "-lna"}

	results, err := testutils.RunNucleiWithArgsAndGetResults(debug, args...)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 0)
}

type headlessHeaderActions struct{}

// Execute executes a test case and returns an error if occurred
func (h *headlessHeaderActions) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		testValue := r.Header.Get("test")
		if r.Header.Get("test") != "" {
			_, _ = w.Write([]byte("<html><body>" + testValue + "</body></html>"))
		}
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-headless")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type headlessExtractValues struct{}

// Execute executes a test case and returns an error if occurred
func (h *headlessExtractValues) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		_, _ = w.Write([]byte("<html><body><a href='/test.html'>test</a></body></html>"))
	})
	ts := httptest.NewServer(router)
	defer ts.Close()
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-headless")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 3)
}

type headlessPayloads struct{}

// Execute executes a test case and returns an error if occurred
func (h *headlessPayloads) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		_, _ = w.Write([]byte("<html><body>test</body></html>"))
	})
	ts := httptest.NewServer(router)
	defer ts.Close()
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-headless")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 4)
}

type headlessVariables struct{}

// Execute executes a test case and returns an error if occurred
func (h *headlessVariables) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		_, _ = w.Write([]byte("<html><body>aGVsbG8=</body></html>"))
	})
	ts := httptest.NewServer(router)
	defer ts.Close()
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-headless")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type headlessFileUpload struct{}

// Execute executes a test case and returns an error if occurred
func (h *headlessFileUpload) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		_, _ = w.Write([]byte(`
		<!doctype html>
			<body>
				<form method=post enctype=multipart/form-data>
				<input type=file name=file>
				<input type=submit value=Upload>
				</form>
			</body>
		</html>
		`))
	})
	router.POST("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		file, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		defer file.Close()

		content, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		_, _ = w.Write(content)
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-headless")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type headlessHeaderStatus struct{}

// Execute executes a test case and returns an error if occurred
func (h *headlessHeaderStatus) Execute(filePath string) error {
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "https://scanme.sh", debug, "-headless")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type headlessFileUploadNegative struct{}

// Execute executes a test case and returns an error if occurred
func (h *headlessFileUploadNegative) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		_, _ = w.Write([]byte(`
		<!doctype html>
			<body>
				<form method=post enctype=multipart/form-data>
				<input type=file name=file>
				<input type=submit value=Upload>
				</form>
			</body>
		</html>
		`))
	})
	router.POST("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		file, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		defer file.Close()

		content, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		_, _ = w.Write(content)
	})
	ts := httptest.NewServer(router)
	defer ts.Close()
	args := []string{"-t", filePath, "-u", ts.URL, "-headless"}

	results, err := testutils.RunNucleiWithArgsAndGetResults(debug, args...)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 0)
}
