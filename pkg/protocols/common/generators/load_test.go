package generators

import (
	"io"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

type fakeCatalog struct{ catalog.Catalog }

func (f *fakeCatalog) OpenFile(filename string) (io.ReadCloser, error) {
	return nil, errors.New("not used")
}
func (f *fakeCatalog) GetTemplatePath(target string) ([]string, error) { return nil, nil }
func (f *fakeCatalog) GetTemplatesPath(definitions []string) ([]string, map[string]error) {
	return nil, nil
}
func (f *fakeCatalog) ResolvePath(templateName, second string) (string, error) {
	return templateName, nil
}

func newTestGenerator() *PayloadGenerator {
	opts := types.DefaultOptions()
	// inject helper loader function
	opts.LoadHelperFileFunction = func(path, templatePath string, _ catalog.Catalog) (io.ReadCloser, error) {
		switch path {
		case "fileA.txt":
			return ioutil.NopCloser(strings.NewReader("one\n two\n\nthree\n")), nil
		default:
			return ioutil.NopCloser(strings.NewReader("x\ny\nz\n")), nil
		}
	}
	return &PayloadGenerator{options: opts, catalog: &fakeCatalog{}}
}

func TestLoadPayloads_FastPathFile(t *testing.T) {
	g := newTestGenerator()
	out, err := g.loadPayloads(map[string]interface{}{"A": "fileA.txt"}, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	got := out["A"]
	if len(got) != 3 || got[0] != "one" || got[1] != " two" || got[2] != "three" {
		t.Fatalf("unexpected: %#v", got)
	}
}

func TestLoadPayloads_InlineMultiline(t *testing.T) {
	g := newTestGenerator()
	inline := "a\nb\n"
	out, err := g.loadPayloads(map[string]interface{}{"B": inline}, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	got := out["B"]
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "" {
		t.Fatalf("unexpected: %#v", got)
	}
}

func TestLoadPayloads_SingleLineFallsBackToFile(t *testing.T) {
	g := newTestGenerator()
	inline := "fileA.txt" // single line, should be treated as file path
	out, err := g.loadPayloads(map[string]interface{}{"C": inline}, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	got := out["C"]
	if len(got) != 3 {
		t.Fatalf("unexpected len: %d", len(got))
	}
}

func TestLoadPayloads_InterfaceSlice(t *testing.T) {
	g := newTestGenerator()
	out, err := g.loadPayloads(map[string]interface{}{"D": []interface{}{"p", "q"}}, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	got := out["D"]
	if len(got) != 2 || got[0] != "p" || got[1] != "q" {
		t.Fatalf("unexpected: %#v", got)
	}
}

func TestLoadPayloadsFromFile_SkipsEmpty(t *testing.T) {
	g := newTestGenerator()
	rc := ioutil.NopCloser(strings.NewReader("a\n\n\n b \n"))
	lines, err := g.loadPayloadsFromFile(rc)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(lines) != 2 || lines[0] != "a" || lines[1] != " b " {
		t.Fatalf("unexpected: %#v", lines)
	}
}
