package generator

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
	"text/template"

	"github.com/pkg/errors"
)

// markdownIndexes is a map of markdown modules to their filename index
//
// It is used to generate the index.md file for the documentation
var markdownIndexes = make(map[string]string)

// WriteGoTemplate writes the go template to the output file
func (d *TemplateData) WriteGoTemplate(outputDirectory string, pkgName string) error {
	_ = os.MkdirAll(outputDirectory, os.ModePerm)

	var err error
	tmpl := template.New("go_class")
	tmpl = tmpl.Funcs(templateFuncs())
	tmpl, err = tmpl.Parse(goClassFile)
	if err != nil {
		return errors.Wrap(err, "could not parse go class template")
	}

	filename := path.Join(outputDirectory, fmt.Sprintf("%s.go", pkgName))
	output, err := os.Create(filename)
	if err != nil {
		return errors.Wrap(err, "could not create go class template")
	}

	if err := tmpl.Execute(output, d); err != nil {
		output.Close()
		return errors.Wrap(err, "could not execute go class template")
	}
	output.Close()

	cmd := exec.Command("gofmt", "-w", filename)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return errors.Wrap(err, "could not format go class template")
	}
	return nil
}

// WriteJSTemplate writes the js template to the output file
func (d *TemplateData) WriteJSTemplate(outputDirectory string, pkgName string) error {
	_ = os.MkdirAll(outputDirectory, os.ModePerm)

	var err error
	tmpl := template.New("js_class")
	tmpl, err = tmpl.Parse(jsClassFile)
	if err != nil {
		return errors.Wrap(err, "could not parse js class template")
	}

	filename := path.Join(outputDirectory, fmt.Sprintf("%s.js", pkgName))
	output, err := os.Create(filename)
	if err != nil {
		return errors.Wrap(err, "could not create js class template")
	}

	if err := tmpl.Execute(output, d); err != nil {
		output.Close()
		return errors.Wrap(err, "could not execute js class template")
	}
	output.Close()

	cmd := exec.Command("js-beautify", "-r", filename)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

// WriteMarkdownIndexTemplate writes the markdown documentation to the output file
func (d *TemplateData) WriteMarkdownIndexTemplate(outputDirectory string) error {
	_ = os.MkdirAll(outputDirectory, os.ModePerm)

	filename := path.Join(outputDirectory, "index.md")
	output, err := os.Create(filename)
	if err != nil {
		return errors.Wrap(err, "could not create markdown index template")
	}
	defer output.Close()

	buffer := &bytes.Buffer{}
	_, _ = buffer.WriteString("# Index\n\n")
	for _, v := range markdownIndexes {
		_, _ = buffer.WriteString(fmt.Sprintf("* %s\n", v))
	}
	_, _ = buffer.WriteString("\n\n")

	_, _ = buffer.WriteString("# Scripts\n\n")
	for _, v := range d.NativeScripts {
		_, _ = buffer.WriteString(fmt.Sprintf("* `%s`\n", v))
	}
	if _, err := output.Write(buffer.Bytes()); err != nil {
		return errors.Wrap(err, "could not write markdown index template")
	}
	return nil
}

// WriteMarkdownLibraryDocumentation writes the markdown documentation for a js library
// to the output file
func (d *TemplateData) WriteMarkdownLibraryDocumentation(outputDirectory string, pkgName string) error {
	var err error
	_ = os.MkdirAll(outputDirectory, os.ModePerm)

	tmpl := template.New("markdown_class")
	tmpl = tmpl.Funcs(templateFuncs())
	tmpl, err = tmpl.Parse(markdownClassFile)
	if err != nil {
		return errors.Wrap(err, "could not parse markdown class template")
	}

	filename := path.Join(outputDirectory, fmt.Sprintf("%s.md", pkgName))
	output, err := os.Create(filename)
	if err != nil {
		return errors.Wrap(err, "could not create markdown class template")
	}

	markdownIndexes[pkgName] = fmt.Sprintf("[%s](%s.md)", pkgName, pkgName)
	if err := tmpl.Execute(output, d); err != nil {
		output.Close()
		return err
	}
	output.Close()

	return nil
}

// templateFuncs returns the template functions for the generator
func templateFuncs() map[string]interface{} {
	return map[string]interface{}{
		"exist": func(v map[string]string, key string) bool {
			_, exist := v[key]
			return exist
		},
		"toTitle": func(v string) string {
			if len(v) == 0 {
				return v
			}

			return strings.ToUpper(string(v[0])) + v[1:]
		},
		"uncomment": func(v string) string {
			return strings.ReplaceAll(strings.ReplaceAll(v, "// ", " "), "\n", " ")
		},
	}
}
