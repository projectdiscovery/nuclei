package output

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
)

func TestStandardWriterRequest(t *testing.T) {
	t.Run("WithoutTraceAndError", func(t *testing.T) {
		w, err := NewStandardWriter(&types.Options{})
		require.NoError(t, err)
		require.NotPanics(t, func() {
			w.Request("path", "input", "http", nil)
			w.Close()
		})
	})

	t.Run("TraceAndErrorWithoutError", func(t *testing.T) {
		traceWriter := &testWriteCloser{}
		errorWriter := &testWriteCloser{}

		w, err := NewStandardWriter(&types.Options{})
		w.traceFile = traceWriter
		w.errorFile = errorWriter
		require.NoError(t, err)
		w.Request("path", "input", "http", nil)

		require.Equal(t, `{"template":"path","type":"http","input":"input","address":"input:","error":"none"}`, traceWriter.String())
		require.Empty(t, errorWriter.String())
	})

	t.Run("ErrorWithWrappedError", func(t *testing.T) {
		errorWriter := &testWriteCloser{}

		w, err := NewStandardWriter(&types.Options{})
		w.errorFile = errorWriter
		require.NoError(t, err)
		w.Request(
			"misconfiguration/tcpconfig.yaml",
			"https://example.com/tcpconfig.html",
			"http",
			fmt.Errorf("GET https://example.com/tcpconfig.html/tcpconfig.html giving up after 2 attempts: %w", errors.New("context deadline exceeded (Client.Timeout exceeded while awaiting headers)")),
		)

		require.Equal(t, `{"template":"misconfiguration/tcpconfig.yaml","type":"http","input":"https://example.com/tcpconfig.html","address":"example.com:443","error":"cause=\"context deadline exceeded (Client.Timeout exceeded while awaiting headers)\"","kind":"unknown-error"}`, errorWriter.String())
	})
}

// Only the fields filled from a response are redacted; text the template wrote
// stays as it is, even next to a filled field.
func TestStandardWriterRedactsFilledInfo(t *testing.T) {
	w, err := NewStandardWriter(&types.Options{Redact: goflags.StringSlice{"password"}})
	require.NoError(t, err)
	w.DisableStdout = true

	written := model.Info{Description: "login with password: {{password}}", Remediation: "Rotate the password: it is public"}
	filled := &ResultEvent{TemplateInfo: &written, Info: model.Info{Description: "login with password: admin", Remediation: written.Remediation}}
	static := &ResultEvent{Info: model.Info{Description: "send the password: header"}}
	require.NoError(t, w.Write(filled))
	require.NoError(t, w.Write(static))

	require.Equal(t, "login with password: ***", filled.Info.Description)
	require.Equal(t, "Rotate the password: it is public", filled.Info.Remediation)
	require.Equal(t, "send the password: header", static.Info.Description)
}

// Credential headers are masked by default; -no-redact keeps them while keys
// given with -redact are still masked.
func TestStandardWriterNoRedact(t *testing.T) {
	const request = "GET /?tracking=1&x=2 HTTP/1.1\r\nCookie: tracking=1; session=abc\r\nX-Token: secret\r\n\r\n"
	const response = "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc; Path=/\r\n\r\n"
	const curl = "curl -H 'Cookie: tracking=1; session=abc' https://example.com/?tracking=1&x=2"
	const matched = "https://example.com/?tracking=1&x=2"

	cases := []struct {
		name     string
		options  *types.Options
		request  string
		response string
		curl     string
		matched  string
	}{
		{
			"default", &types.Options{},
			"GET /?tracking=1&x=2 HTTP/1.1\r\nCookie: ***\r\nX-Token: secret\r\n\r\n",
			"HTTP/1.1 200 OK\r\nSet-Cookie: ***\r\n\r\n",
			"curl -H 'Cookie: ***' https://example.com/?tracking=1&x=2",
			matched,
		},
		{"no-redact", &types.Options{NoRedact: true}, request, response, curl, matched},
		{
			"no-redact with header key", &types.Options{NoRedact: true, Redact: goflags.StringSlice{"X-Token"}},
			"GET /?tracking=1&x=2 HTTP/1.1\r\nCookie: tracking=1; session=abc\r\nX-Token: ***\r\n\r\n",
			response, curl, matched,
		},
		// One cookie or query parameter is masked; its neighbours stay.
		{
			"no-redact with cookie key", &types.Options{NoRedact: true, Redact: goflags.StringSlice{"tracking"}},
			"GET /?tracking=***&x=2 HTTP/1.1\r\nCookie: tracking=***; session=abc\r\nX-Token: secret\r\n\r\n",
			response,
			"curl -H 'Cookie: tracking=***; session=abc' https://example.com/?tracking=***&x=2",
			"https://example.com/?tracking=***&x=2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := NewStandardWriter(tc.options)
			require.NoError(t, err)
			w.DisableStdout = true

			event := &ResultEvent{Request: request, Response: response, CURLCommand: curl, Matched: matched}
			require.NoError(t, w.Write(event))

			require.Equal(t, tc.request, event.Request)
			require.Equal(t, tc.response, event.Response)
			require.Equal(t, tc.curl, event.CURLCommand)
			require.Equal(t, tc.matched, event.Matched)
		})
	}
}

// A `;` inside a query value is part of the value; in a cookie header it is a delimiter.
func TestRedactKeepsSemicolonInsideValue(t *testing.T) {
	cases := map[string]string{
		"GET /?password=;s3cr3t&x=2 HTTP/1.1":             "GET /?password=***&x=2 HTTP/1.1",
		"GET /?password=a;b HTTP/1.1":                     "GET /?password=*** HTTP/1.1",
		"GET /?password=super;secret=hidden&x=1 HTTP/1.1": "GET /?password=***&x=1 HTTP/1.1",
		"https://example.com/?password=a;b":               "https://example.com/?password=***",
		"https://example.com/?password=a;session=abc":     "https://example.com/?password=***",
		"Cookie: password=x; session=abc\r\n":             "Cookie: password=***; session=abc\r\n",
		"Set-Cookie: password=x; Path=/; HttpOnly\r\n":    "Set-Cookie: password=***; Path=/; HttpOnly\r\n",
		"Set-Cookie: password=x; HttpOnly\r\n":            "Set-Cookie: password=***; HttpOnly\r\n",
		"password=a;b&user=u":                             "password=***&user=u",
		"curl -H 'Cookie: password=x; session=abc' 'https://example.com/?password=super;secret=hidden&x=1'": "curl -H 'Cookie: password=***; session=abc' 'https://example.com/?password=***&x=1'",
	}
	for in, want := range cases {
		require.Equal(t, want, redactKeys(in, []string{"password"}), in)
	}
}

// The mongo exporter serializes results with bson, which ignores json tags.
func TestResultEventKeepsTemplateInfoOutOfBSON(t *testing.T) {
	written := model.Info{Description: "{{host}} is exposed"}
	data, err := bson.Marshal(&ResultEvent{TemplateInfo: &written, Info: model.Info{Description: "example.com is exposed"}})
	require.NoError(t, err)

	var doc bson.M
	require.NoError(t, bson.Unmarshal(data, &doc))
	require.NotContains(t, doc, "templateinfo")
	require.Contains(t, doc, "info")
}

// Template YAML decodes nested maps with interface keys, in the info metadata and
// in the javascript args a result carries as its metadata.
func TestFormatJSONNestedYAMLMaps(t *testing.T) {
	var template struct {
		Info model.Info             `yaml:"info"`
		Args map[string]interface{} `yaml:"args"`
	}
	err := yaml.Unmarshal([]byte(`
info:
  name: Nested metadata
  author: repro
  severity: info
  metadata:
    labels:
      en: Hello
    items:
      - fr: Bonjour
args:
  Nested:
    en: Hello
`), &template)
	require.NoError(t, err)

	w, err := NewStandardWriter(&types.Options{JSONL: true})
	require.NoError(t, err)
	data, err := w.formatJSON(&ResultEvent{TemplateID: "nested-metadata", Info: template.Info, Metadata: template.Args})
	require.NoError(t, err)

	var decoded struct {
		Info struct {
			Metadata map[string]interface{} `json:"metadata"`
		} `json:"info"`
		Meta map[string]interface{} `json:"meta"`
	}
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, map[string]interface{}{
		"labels": map[string]interface{}{"en": "Hello"},
		"items":  []interface{}{map[string]interface{}{"fr": "Bonjour"}},
	}, decoded.Info.Metadata)
	require.Equal(t, map[string]interface{}{"Nested": map[string]interface{}{"en": "Hello"}}, decoded.Meta)
}

type testWriteCloser struct {
	strings.Builder
}

func (w testWriteCloser) Close() error {
	return nil
}


func TestFormatJSONSanitizesNestedMetadataMaps(t *testing.T) {
	w, err := NewStandardWriter(&types.Options{})
	require.NoError(t, err)

	event := &ResultEvent{
		TemplateID: "nested-metadata",
		Type:       "file",
		Host:       "target",
		Matched:    "target/input.txt",
		Info: model.Info{
			Name: "Nested metadata",
			Metadata: map[string]interface{}{
				"labels": map[interface{}]interface{}{
					"en": "Hello",
					"nested_list": []interface{}{
						map[interface{}]interface{}{
							"inner_key": "inner_val",
						},
					},
				},
			},
		},
	}

	data, err := w.formatJSON(event)
	require.NoError(t, err, "formatJSON should not fail on nested map[interface{}]interface{} (#7971)")
	require.Contains(t, string(data), `"labels":{"en":"Hello","nested_list":[{"inner_key":"inner_val"}]}`)
}

// ---------------------------------------------------------------------------
// Path-traversal containment tests for sanitizeFileName and WriteStoreDebugData
// (CWE-22, defense-in-depth – mirrors the markdown exporter's regression suite)
// ---------------------------------------------------------------------------

// TestSanitizeFileNameContainment verifies that sanitizeFileName strips every
// character that could allow a path to escape its intended directory. The
// markdown exporter has an equivalent fuzz-driven suite; this test covers the
// same invariants for the output writer's sanitizer.
func TestSanitizeFileNameContainment(t *testing.T) {
	reportDir := t.TempDir()

	hostileInputs := []string{
		"../../etc/passwd",
		"..\\..\\Windows\\System32",
		"..",
		"http://evil.com/../../../etc/shadow",
		"https://attacker.example/../../../../root/.ssh/authorized_keys",
		"some/host/../../escape",
		strings.Repeat("../", 200) + "etc/passwd",
		strings.Repeat("..\\", 200) + "Windows",
		"...",
		"....",
		".....",
		"\x00/etc/passwd", // null byte (not a real traversal on Linux but should be safe)
		"/../../foo",
		"\\..\\..\\foo",
	}

	for _, in := range hostileInputs {
		in := in // capture
		t.Run(in, func(t *testing.T) {
			out := sanitizeFileName(in)
			// After sanitisation no path separator must survive.
			require.False(t, strings.ContainsAny(out, "/\\"),
				"sanitizeFileName leaked a separator: in=%q out=%q", in, out)
			// No ".." parent-ref must survive either.
			require.False(t, strings.Contains(out, ".."),
				"sanitizeFileName leaked '..': in=%q out=%q", in, out)

			// Joining the sanitised value with an arbitrary base must stay
			// inside that base – the same invariant the exporter relies on.
			joined := filepath.Clean(filepath.Join(reportDir, out))
			rel, err := filepath.Rel(reportDir, joined)
			require.NoError(t, err)
			require.NotEqual(t, "..", rel)
			require.False(t, strings.HasPrefix(rel, ".."+string(filepath.Separator)),
				"sanitizeFileName: joined path escaped reportDir: in=%q out=%q rel=%q", in, out, rel)
		})
	}
}

// TestWriteStoreDebugDataContainment is an integration test that calls
// WriteStoreDebugData with attacker-shaped host / templateID values and verifies
// that no file is ever created outside the configured storeResponseDir.
// Without the containment guard added in this fix, a future regression in
// sanitizeFileName could silently allow a file to escape; this test would catch
// such a regression immediately.
func TestWriteStoreDebugDataContainment(t *testing.T) {
	storeDir := t.TempDir()

	w := &StandardWriter{
		storeResponse:    true,
		storeResponseDir: storeDir,
	}

	hostilePairs := []struct{ host, templateID string }{
		{"../../etc/passwd", "cve-2023-1234"},
		{"..\\..\\Windows\\system32", "cve-2023-1234"},
		{"http://evil.com/../../../etc/shadow", "poc"},
		{"https://attacker.example/" + strings.Repeat("../", 50) + "root/.ssh", "recon"},
		{"..", ".."},
		{"/etc/passwd", "test"},
		{"\\\\unc\\path\\..\\evil", "smb-test"},
	}

	for _, tc := range hostilePairs {
		tc := tc
		t.Run(tc.host+"|"+tc.templateID, func(t *testing.T) {
			w.WriteStoreDebugData(tc.host, tc.templateID, "http", "debug-data")
		})
	}

	// Walk storeDir and assert every file created is still inside it.
	err := filepath.Walk(storeDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, relErr := filepath.Rel(storeDir, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil // the root itself
		}
		require.False(t, strings.HasPrefix(rel, ".."),
			"WriteStoreDebugData created a file outside store dir: %s", path)
		return nil
	})
	require.NoError(t, err)
}
