package templates_test

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
)

func BenchmarkParse(b *testing.B) {
	filePath := "tests/match-1.yaml"

	setup()
	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		_, err := templates.Parse(filePath, nil, executerOpts)
		if err != nil {
			b.Fatalf("could not parse template: %s", err)
		}
	}
}

func BenchmarkParseTemplateFromReader(b *testing.B) {
	filePath := "tests/match-1.yaml"

	file, err := os.Open(filePath)
	if err != nil {
		b.Fatalf("could not open template file: %s", err)
	}
	defer func() {
		_ = file.Close()
	}()

	content, err := io.ReadAll(file)
	if err != nil {
		b.Fatalf("could not read template file: %s", err)
	}

	setup()

	// Prepare the options with template path set.
	//
	// TODO(dwisiswant0): ParseTemplateFromReader should ideally work with just
	// a reader without requiring path information, making it more flexible for
	// in-memory templates or templates from non-file sources, the function
	// unnecessarily couples the parsing logic to filepath info when it should
	// primarily care about the content because it only needs a reader, but it
	// actually requires path information in the options.
	//
	// The current implementation fails with a confusing error about template
	// format detection, "no template name field provided", rather than
	// explicitly stating that a path is required.
	opts := executerOpts.Copy()
	opts.TemplatePath = filePath

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		reader := bytes.NewReader(content)
		_, err := templates.ParseTemplateFromReader(reader, nil, opts)
		if err != nil {
			b.Fatalf("could not parse template from reader: %s", err)
		}
	}
}
