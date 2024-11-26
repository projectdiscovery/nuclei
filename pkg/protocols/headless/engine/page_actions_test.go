package engine

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils/testheadless"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

func TestActionNavigate(t *testing.T) {
	response := `
		<html>
		<head>
			<title>Nuclei Test Page</title>
		</head>
		<body>
			<h1>Nuclei Test</h1>
		</body>
	</html>`

	actions := []*Action{{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}}, {ActionType: ActionTypeHolder{ActionType: ActionWaitLoad}}}

	testHeadlessSimpleResponse(t, response, actions, 20*time.Second, func(page *Page, err error, out ActionData) {
		require.Nilf(t, err, "could not run page actions")
		require.Equal(t, "Nuclei Test Page", page.Page().MustInfo().Title, "could not navigate correctly")
	})
}

func TestActionScript(t *testing.T) {
	response := `
		<html>
		<head>
			<title>Nuclei Test Page</title>
		</head>
		<body>Nuclei Test Page</body>
		<script>window.test = 'some-data';</script>
	</html>`

	timeout := 180 * time.Second

	t.Run("run-and-results", func(t *testing.T) {
		actions := []*Action{
			{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
			{ActionType: ActionTypeHolder{ActionType: ActionWaitLoad}},
			{ActionType: ActionTypeHolder{ActionType: ActionScript}, Name: "test", Data: map[string]string{"code": "() => window.test"}},
		}

		testHeadlessSimpleResponse(t, response, actions, timeout, func(page *Page, err error, out ActionData) {
			require.Nil(t, err, "could not run page actions")
			require.Equal(t, "Nuclei Test Page", page.Page().MustInfo().Title, "could not navigate correctly")
			require.Equal(t, "some-data", out["test"], "could not run js and get results correctly")
		})
	})

	t.Run("hook", func(t *testing.T) {
		actions := []*Action{
			{ActionType: ActionTypeHolder{ActionType: ActionScript}, Data: map[string]string{"code": "() => window.test = 'some-data';", "hook": "true"}},
			{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
			{ActionType: ActionTypeHolder{ActionType: ActionWaitLoad}},
			{ActionType: ActionTypeHolder{ActionType: ActionScript}, Name: "test", Data: map[string]string{"code": "() => window.test"}},
		}
		testHeadlessSimpleResponse(t, response, actions, timeout, func(page *Page, err error, out ActionData) {
			require.Nil(t, err, "could not run page actions")
			require.Equal(t, "Nuclei Test Page", page.Page().MustInfo().Title, "could not navigate correctly")
			require.Equal(t, "some-data", out["test"], "could not run js and get results correctly with js hook")
		})
	})
}

func TestActionClick(t *testing.T) {
	response := `
		<html>
			<head>
				<title>Nuclei Test Page</title>
			</head>
			<body>Nuclei Test Page</body>
			<button onclick='this.setAttribute("a", "ok")'>click me</button>
		</html>`

	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionWaitLoad}},
		{ActionType: ActionTypeHolder{ActionType: ActionClick}, Data: map[string]string{"selector": "button"}}, // Use css selector for clicking
	}

	testHeadlessSimpleResponse(t, response, actions, 20*time.Second, func(page *Page, err error, out ActionData) {
		require.Nil(t, err, "could not run page actions")
		require.Equal(t, "Nuclei Test Page", page.Page().MustInfo().Title, "could not navigate correctly")
		el := page.Page().MustElement("button")
		val := el.MustAttribute("a")
		require.Equal(t, "ok", *val, "could not click button")
	})
}

func TestActionRightClick(t *testing.T) {
	response := `
		<html>
			<head>
				<title>Nuclei Test Page</title>
			</head>
			<body>Nuclei Test Page</body>
			<button id="test" onrightclick=''>click me</button>
			<script>
				elm = document.getElementById("test");
				elm.onmousedown = function(event) {
					if (event.which == 3) {
						elm.setAttribute("a", "ok")
					}
				}
			</script>
		</html>`

	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionWaitLoad}},
		{ActionType: ActionTypeHolder{ActionType: ActionRightClick}, Data: map[string]string{"selector": "button"}}, // Use css selector for clicking
	}

	testHeadlessSimpleResponse(t, response, actions, 20*time.Second, func(page *Page, err error, out ActionData) {
		require.Nil(t, err, "could not run page actions")
		require.Equal(t, "Nuclei Test Page", page.Page().MustInfo().Title, "could not navigate correctly")
		el := page.Page().MustElement("button")
		val := el.MustAttribute("a")
		require.Equal(t, "ok", *val, "could not click button")
	})
}

func TestActionTextInput(t *testing.T) {
	response := `
		<html>
			<head>
				<title>Nuclei Test Page</title>
			</head>
			<body>Nuclei Test Page</body>
			<input type="text" onchange="this.setAttribute('event', 'input-change')">
		</html>`

	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionWaitLoad}},
		{ActionType: ActionTypeHolder{ActionType: ActionTextInput}, Data: map[string]string{"selector": "input", "value": "test"}},
	}

	testHeadlessSimpleResponse(t, response, actions, 20*time.Second, func(page *Page, err error, out ActionData) {
		require.Nil(t, err, "could not run page actions")
		require.Equal(t, "Nuclei Test Page", page.Page().MustInfo().Title, "could not navigate correctly")
		el := page.Page().MustElement("input")
		val := el.MustAttribute("event")
		require.Equal(t, "input-change", *val, "could not get input change")
		require.Equal(t, "test", el.MustText(), "could not get input change value")
	})
}

func TestActionHeadersChange(t *testing.T) {
	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionSetHeader}, Data: map[string]string{"part": "request", "key": "Test", "value": "Hello"}},
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionWaitLoad}},
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Test") == "Hello" {
			_, _ = fmt.Fprintln(w, `found`)
		}
	}

	testHeadless(t, actions, 20*time.Second, handler, func(page *Page, err error, out ActionData) {
		require.Nil(t, err, "could not run page actions")
		require.Equal(t, "found", strings.ToLower(strings.TrimSpace(page.Page().MustElement("html").MustText())), "could not set header correctly")
	})
}

func TestActionScreenshot(t *testing.T) {
	response := `
		<html>
			<head>
				<title>Nuclei Test Page</title>
			</head>
			<body>Nuclei Test Page</body>
		</html>`

	// filePath where screenshot is saved
	filePath := filepath.Join(os.TempDir(), "test.png")
	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionWaitFMP}},
		{ActionType: ActionTypeHolder{ActionType: ActionScreenshot}, Data: map[string]string{"to": filePath}},
	}

	testHeadlessSimpleResponse(t, response, actions, 20*time.Second, func(page *Page, err error, out ActionData) {
		require.Nil(t, err, "could not run page actions")
		require.Equal(t, "Nuclei Test Page", page.Page().MustInfo().Title, "could not navigate correctly")
		_ = page.Page()
		require.FileExists(t, filePath, "could not find screenshot file %v", filePath)
		if err := os.RemoveAll(filePath); err != nil {
			t.Logf("got error %v while deleting temp file", err)
		}
	})
}

func TestActionScreenshotToDir(t *testing.T) {
	response := `
		<html>
			<head>
				<title>Nuclei Test Page</title>
			</head>
			<body>Nuclei Test Page</body>
		</html>`

	filePath := filepath.Join(os.TempDir(), "screenshot-"+strconv.Itoa(rand.Intn(1000)), "test.png")

	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionWaitFMP}},
		{ActionType: ActionTypeHolder{ActionType: ActionScreenshot}, Data: map[string]string{"to": filePath, "mkdir": "true"}},
	}

	testHeadlessSimpleResponse(t, response, actions, 20*time.Second, func(page *Page, err error, out ActionData) {
		require.Nil(t, err, "could not run page actions")
		require.Equal(t, "Nuclei Test Page", page.Page().MustInfo().Title, "could not navigate correctly")
		_ = page.Page()
		require.FileExists(t, filePath, "could not find screenshot file %v", filePath)
		if err := os.RemoveAll(filePath); err != nil {
			t.Logf("got error %v while deleting temp file", err)
		}
	})
}

func TestActionTimeInput(t *testing.T) {
	response := `
		<html>
			<head>
				<title>Nuclei Test Page</title>
			</head>
			<body>Nuclei Test Page</body>
			<input type="date">
		</html>`

	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionWaitLoad}},
		{ActionType: ActionTypeHolder{ActionType: ActionTimeInput}, Data: map[string]string{"selector": "input", "value": "2006-01-02T15:04:05Z"}},
	}

	testHeadlessSimpleResponse(t, response, actions, 20*time.Second, func(page *Page, err error, out ActionData) {
		require.Nil(t, err, "could not run page actions")
		require.Equal(t, "Nuclei Test Page", page.Page().MustInfo().Title, "could not navigate correctly")
		el := page.Page().MustElement("input")
		require.Equal(t, "2006-01-02", el.MustText(), "could not get input time value")
	})
}

func TestActionSelectInput(t *testing.T) {
	response := `
		<html>
			<head>
				<title>Nuclei Test Page</title>
			</head>
			<body>
				<select name="test" id="test">
				  <option value="test1">Test1</option>
				  <option value="test2">Test2</option>
				</select>
			</body>
		</html>`

	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionWaitLoad}},
		{ActionType: ActionTypeHolder{ActionType: ActionSelectInput}, Data: map[string]string{"by": "x", "xpath": "//select[@id='test']", "value": "Test2", "selected": "true"}},
	}

	testHeadlessSimpleResponse(t, response, actions, 20*time.Second, func(page *Page, err error, out ActionData) {
		require.Nil(t, err, "could not run page actions")
		el := page.Page().MustElement("select")
		require.Equal(t, "Test2", el.MustText(), "could not get input change value")
	})
}

func TestActionFilesInput(t *testing.T) {
	response := `
		<html>
			<head>
				<title>Nuclei Test Page</title>
			</head>
			<body>Nuclei Test Page</body>
			<input type="file">
		</html>`

	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionWaitLoad}},
		{ActionType: ActionTypeHolder{ActionType: ActionFilesInput}, Data: map[string]string{"selector": "input", "value": "test1.pdf"}},
	}

	testHeadlessSimpleResponse(t, response, actions, 20*time.Second, func(page *Page, err error, out ActionData) {
		require.Nil(t, err, "could not run page actions")
		require.Equal(t, "Nuclei Test Page", page.Page().MustInfo().Title, "could not navigate correctly")
		el := page.Page().MustElement("input")
		require.Equal(t, "C:\\fakepath\\test1.pdf", el.MustText(), "could not get input file")
	})
}

// Negative testcase for files input where it should fail
func TestActionFilesInputNegative(t *testing.T) {
	response := `
		<html>
			<head>
				<title>Nuclei Test Page</title>
			</head>
			<body>Nuclei Test Page</body>
			<input type="file">
		</html>`

	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionWaitLoad}},
		{ActionType: ActionTypeHolder{ActionType: ActionFilesInput}, Data: map[string]string{"selector": "input", "value": "test1.pdf"}},
	}
	t.Setenv("LOCAL_FILE_ACCESS", "false")

	testHeadlessSimpleResponse(t, response, actions, 20*time.Second, func(page *Page, err error, out ActionData) {
		require.ErrorContains(t, err, ErrLFAccessDenied.Error(), "got file access when -lfa is false")
	})
}

func TestActionWaitLoad(t *testing.T) {
	response := `
		<html>
			<head>
				<title>Nuclei Test Page</title>
			</head>
			<button id="test">Wait for me!</button>
			<script>
				window.onload = () => document.querySelector('#test').style.color = 'red';
			</script>
		</html>`

	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionWaitLoad}},
	}

	testHeadlessSimpleResponse(t, response, actions, 20*time.Second, func(page *Page, err error, out ActionData) {
		require.Nil(t, err, "could not run page actions")
		el := page.Page().MustElement("button")
		style, attributeErr := el.Attribute("style")
		require.Nil(t, attributeErr)
		require.Equal(t, "color: red;", *style, "could not get color")
	})
}

func TestActionGetResource(t *testing.T) {
	response := `
		<html>
			<head>
				<title>Nuclei Test Page</title>
			</head>
			<body>
				<img id="test" src="https://raw.githubusercontent.com/projectdiscovery/wallpapers/main/pd-floppy.jpg">
			</body>
		</html>`

	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionGetResource}, Data: map[string]string{"by": "x", "xpath": "//img[@id='test']"}, Name: "src"},
	}

	testHeadlessSimpleResponse(t, response, actions, 20*time.Second, func(page *Page, err error, out ActionData) {
		require.Nil(t, err, "could not run page actions")

		src, ok := out["src"].(string)
		require.True(t, ok, "could not assert src to string")
		require.Equal(t, len(src), 121808, "could not find resource")
	})
}

func TestActionExtract(t *testing.T) {
	response := `
		<html>
			<head>
				<title>Nuclei Test Page</title>
			</head>
			<button id="test">Wait for me!</button>
		</html>`

	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionExtract}, Data: map[string]string{"by": "x", "xpath": "//button[@id='test']"}, Name: "extract"},
	}

	testHeadlessSimpleResponse(t, response, actions, 20*time.Second, func(page *Page, err error, out ActionData) {
		require.Nil(t, err, "could not run page actions")
		require.Equal(t, "Wait for me!", out["extract"], "could not extract text")
	})
}

func TestActionSetMethod(t *testing.T) {
	response := `
		<html>
			<head>
				<title>Nuclei Test Page</title>
			</head>
		</html>`

	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionSetMethod}, Data: map[string]string{"part": "x", "method": "SET"}},
	}

	testHeadlessSimpleResponse(t, response, actions, 20*time.Second, func(page *Page, err error, out ActionData) {
		require.Nil(t, err, "could not run page actions")
		require.Equal(t, "SET", page.rules[0].Args["method"], "could not find resource")
	})
}

func TestActionAddHeader(t *testing.T) {
	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionAddHeader}, Data: map[string]string{"part": "request", "key": "Test", "value": "Hello"}},
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionWaitLoad}},
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Test") == "Hello" {
			_, _ = fmt.Fprintln(w, `found`)
		}
	}

	testHeadless(t, actions, 20*time.Second, handler, func(page *Page, err error, out ActionData) {
		require.Nil(t, err, "could not run page actions")
		require.Equal(t, "found", strings.ToLower(strings.TrimSpace(page.Page().MustElement("html").MustText())), "could not set header correctly")
	})
}

func TestActionDeleteHeader(t *testing.T) {
	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionAddHeader}, Data: map[string]string{"part": "request", "key": "Test1", "value": "Hello"}},
		{ActionType: ActionTypeHolder{ActionType: ActionAddHeader}, Data: map[string]string{"part": "request", "key": "Test2", "value": "World"}},
		{ActionType: ActionTypeHolder{ActionType: ActionDeleteHeader}, Data: map[string]string{"part": "request", "key": "Test2"}},
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionWaitLoad}},
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Test1") == "Hello" && r.Header.Get("Test2") == "" {
			_, _ = fmt.Fprintln(w, `header deleted`)
		}
	}

	testHeadless(t, actions, 20*time.Second, handler, func(page *Page, err error, out ActionData) {
		require.Nil(t, err, "could not run page actions")
		require.Equal(t, "header deleted", strings.ToLower(strings.TrimSpace(page.Page().MustElement("html").MustText())), "could not delete header correctly")
	})
}

func TestActionSetBody(t *testing.T) {
	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionSetBody}, Data: map[string]string{"part": "request", "body": "hello"}},
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionWaitLoad}},
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = fmt.Fprintln(w, string(body))
	}

	testHeadless(t, actions, 20*time.Second, handler, func(page *Page, err error, out ActionData) {
		require.Nil(t, err, "could not run page actions")
		require.Equal(t, "hello", strings.ToLower(strings.TrimSpace(page.Page().MustElement("html").MustText())), "could not set header correctly")
	})
}

func TestActionKeyboard(t *testing.T) {
	response := `
		<html>
			<head>
				<title>Nuclei Test Page</title>
			</head>
			<body>
				<input type="text" name="test" id="test">
			</body>
		</html>`

	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionWaitLoad}},
		{ActionType: ActionTypeHolder{ActionType: ActionClick}, Data: map[string]string{"selector": "input"}},
		{ActionType: ActionTypeHolder{ActionType: ActionKeyboard}, Data: map[string]string{"keys": "Test2"}},
	}

	testHeadlessSimpleResponse(t, response, actions, 20*time.Second, func(page *Page, err error, out ActionData) {
		require.Nil(t, err, "could not run page actions")
		el := page.Page().MustElement("input")
		require.Equal(t, "Test2", el.MustText(), "could not get input change value")
	})
}

func TestActionSleep(t *testing.T) {
	response := `
		<html>
			<head>
				<title>Nuclei Test Page</title>
			</head>
			<button style="display:none" id="test">Wait for me!</button>
			<script>
				setTimeout(() => document.querySelector('#test').style.display = '', 1000);
			</script>
		</html>`

	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionSleep}, Data: map[string]string{"duration": "2"}},
	}

	testHeadlessSimpleResponse(t, response, actions, 20*time.Second, func(page *Page, err error, out ActionData) {
		require.Nil(t, err, "could not run page actions")
		require.True(t, page.Page().MustElement("button").MustVisible(), "could not get button")
	})
}

func TestActionWaitVisible(t *testing.T) {
	response := `
		<html>
			<head>
				<title>Nuclei Test Page</title>
			</head>
			<button style="display:none" id="test">Wait for me!</button>
			<script>
				setTimeout(() => document.querySelector('#test').style.display = '', 1000);
			</script>
		</html>`

	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionWaitVisible}, Data: map[string]string{"by": "x", "xpath": "//button[@id='test']"}},
	}

	t.Run("wait for an element being visible", func(t *testing.T) {
		testHeadlessSimpleResponse(t, response, actions, 2*time.Second, func(page *Page, err error, out ActionData) {
			require.Nil(t, err, "could not run page actions")

			page.Page().MustElement("button").MustVisible()
		})
	})

	t.Run("timeout because of element not visible", func(t *testing.T) {
		// increased timeout from time.Second/2 to time.Second due to random fails (probably due to overhead and system)
		testHeadlessSimpleResponse(t, response, actions, time.Second, func(page *Page, err error, out ActionData) {
			require.Error(t, err)
			require.Contains(t, err.Error(), "Element did not appear in the given amount of time")
		})
	})
}

func TestActionWaitDialog(t *testing.T) {
	response := `<html>
		<head>
			<title>Nuclei Test Page</title>
		</head>
		<body>
		<script type="text/javascript">
		const urlParams = new URLSearchParams(window.location.search);
		const scriptContent = urlParams.get('script');
		if (scriptContent) {
		  const scriptElement = document.createElement('script');
		  scriptElement.textContent = scriptContent;

		  document.body.appendChild(scriptElement);
		}
		</script>
		</body>
	</html>`

	t.Run("Triggered", func(t *testing.T) {
		actions := []*Action{
			{
				ActionType: ActionTypeHolder{ActionType: ActionNavigate},
				Data:       map[string]string{"url": "{{BaseURL}}/?script=alert%281%29"},
			},
			{
				ActionType: ActionTypeHolder{ActionType: ActionWaitDialog},
				Name:       "test",
			},
		}

		testHeadlessSimpleResponse(t, response, actions, 1*time.Second, func(page *Page, err error, out ActionData) {
			require.Nil(t, err, "could not run page actions")

			test, ok := out["test"].(bool)
			require.True(t, ok, "could not assert test to bool")
			require.True(t, test, "could not find test")
		})
	})

	t.Run("Invalid", func(t *testing.T) {
		actions := []*Action{
			{
				ActionType: ActionTypeHolder{ActionType: ActionNavigate},
				Data:       map[string]string{"url": "{{BaseURL}}/?script=foo"},
			},
			{
				ActionType: ActionTypeHolder{ActionType: ActionWaitDialog},
				Name:       "test",
			},
		}

		testHeadlessSimpleResponse(t, response, actions, 1*time.Second, func(page *Page, err error, out ActionData) {
			require.Nil(t, err, "could not run page actions")

			_, ok := out["test"].(bool)
			require.False(t, ok, "output assertion is success")
		})
	})
}

func testHeadlessSimpleResponse(t *testing.T, response string, actions []*Action, timeout time.Duration, assert func(page *Page, pageErr error, out ActionData)) {
	t.Helper()
	testHeadless(t, actions, timeout, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, response)
	}, assert)
}

func testHeadless(t *testing.T, actions []*Action, timeout time.Duration, handler func(w http.ResponseWriter, r *http.Request), assert func(page *Page, pageErr error, extractedData ActionData)) {
	t.Helper()

	lfa := getBoolFromEnv("LOCAL_FILE_ACCESS", true)
	rna := getBoolFromEnv("RESTRICED_LOCAL_NETWORK_ACCESS", false)
	opts := &types.Options{AllowLocalFileAccess: lfa, RestrictLocalNetworkAccess: rna}

	_ = protocolstate.Init(opts)

	browser, err := New(&types.Options{ShowBrowser: false, UseInstalledChrome: testheadless.HeadlessLocal})
	require.Nil(t, err, "could not create browser")
	defer browser.Close()

	instance, err := browser.NewInstance()
	require.Nil(t, err, "could not create browser instance")
	defer instance.Close()

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	input := contextargs.NewWithInput(context.Background(), ts.URL)
	input.CookieJar, err = cookiejar.New(nil)
	require.Nil(t, err)

	extractedData, page, err := instance.Run(input, actions, nil, &Options{Timeout: timeout, Options: opts}) // allow file access in test
	assert(page, err, extractedData)

	if page != nil {
		page.Close()
	}
}

func TestContainsAnyModificationActionType(t *testing.T) {
	if containsAnyModificationActionType() {
		t.Error("Expected false, got true")
	}
	if containsAnyModificationActionType(ActionClick) {
		t.Error("Expected false, got true")
	}
	if !containsAnyModificationActionType(ActionSetMethod, ActionAddHeader, ActionExtract) {
		t.Error("Expected true, got false")
	}
	if !containsAnyModificationActionType(ActionSetMethod, ActionAddHeader, ActionSetHeader, ActionDeleteHeader, ActionSetBody) {
		t.Error("Expected true, got false")
	}
}

func TestBlockedHeadlessURLS(t *testing.T) {

	// run this test from binary since we are changing values
	// of global variables
	if os.Getenv("TEST_BLOCK_HEADLESS_URLS") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=TestBlockedHeadlessURLS", "-test.v")
		cmd.Env = append(cmd.Env, "TEST_BLOCK_HEADLESS_URLS=1")
		out, err := cmd.CombinedOutput()
		if !strings.Contains(string(out), "PASS\n") || err != nil {
			t.Fatalf("%s\n(exit status %v)", string(out), err)
		}
		return
	}

	opts := &types.Options{
		AllowLocalFileAccess:       false,
		RestrictLocalNetworkAccess: true,
	}
	err := protocolstate.Init(opts)
	require.Nil(t, err, "could not init protocol state")

	browser, err := New(&types.Options{ShowBrowser: false, UseInstalledChrome: testheadless.HeadlessLocal})
	require.Nil(t, err, "could not create browser")
	defer browser.Close()

	instance, err := browser.NewInstance()
	require.Nil(t, err, "could not create browser instance")
	defer instance.Close()

	ts := httptest.NewServer(nil)
	defer ts.Close()

	testcases := []string{
		"file:/etc/hosts",
		" file:///etc/hosts\r\n",
		"	fILe:/../../../../etc/hosts",
		ts.URL, // local test server
		"fTP://example.com:21\r\n",
		"ftp://example.com:21",
		"chrome://settings",
		"	chROme://version",
		"chrome-extension://version\r",
		"	chrOme-EXTension://settings",
		"view-source:file:/etc/hosts",
	}

	for _, testcase := range testcases {
		actions := []*Action{
			{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": testcase}},
			{ActionType: ActionTypeHolder{ActionType: ActionWaitLoad}},
		}

		data, page, err := instance.Run(contextargs.NewWithInput(context.Background(), ts.URL), actions, nil, &Options{Timeout: 20 * time.Second, Options: opts}) // allow file access in test
		require.Error(t, err, "expected error for url %s got %v", testcase, data)
		require.True(t, stringsutil.ContainsAny(err.Error(), "net::ERR_ACCESS_DENIED", "failed to parse url", "Cannot navigate to invalid URL", "net::ERR_ABORTED", "net::ERR_INVALID_URL"), "found different error %v for testcases %v", err, testcase)
		require.Len(t, data, 0, "expected no data for url %s got %v", testcase, data)
		if page != nil {
			page.Close()
		}
	}
}

func getBoolFromEnv(key string, defaultValue bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultValue
	}
	return strings.EqualFold(val, "true")
}
