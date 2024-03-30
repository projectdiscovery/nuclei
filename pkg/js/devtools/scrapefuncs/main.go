package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	mapsutil "github.com/projectdiscovery/utils/maps"
)

var (
	dir string
	out string
)

type DSLHelperFunc struct {
	Name        string
	Description string
	Signatures  []string
}

var pkg2NameMapping = map[string]string{
	"code":       "Code Protocol",
	"javascript": "JavaScript Protocol",
	"global":     "Javascript Runtime",
	"compiler":   "Javascript Runtime",
}

func main() {
	flag.StringVar(&dir, "dir", "pkg/", "directory to process")
	flag.StringVar(&out, "out", "", "output markdown file with helper file declarations")
	flag.Parse()

	dirList := []string{}

	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if d.IsDir() {
			dirList = append(dirList, path)
		}
		return nil
	})
	pkgs := map[string]*ast.Package{}

	for _, dir := range dirList {
		fset := token.NewFileSet()
		pkgss, err := parser.ParseDir(fset, dir, nil, 0)
		if err != nil {
			fmt.Println(err)
			return
		}
		pkgs = mapsutil.Merge(pkgs, pkgss)
	}

	dslHelpers := map[string][]DSLHelperFunc{}

	for _, pkg := range pkgs {
		for fname, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
						if sel.Sel.Name == "RegisterFuncWithSignature" {
							hf := DSLHelperFunc{}
							for _, arg := range x.Args {
								if kv, ok := arg.(*ast.CompositeLit); ok {
									for _, elt := range kv.Elts {
										if kv, ok := elt.(*ast.KeyValueExpr); ok {
											key := kv.Key.(*ast.Ident).Name
											switch key {
											case "Name":
												hf.Name = strings.Trim(kv.Value.(*ast.BasicLit).Value, `"`)
											case "Description":
												hf.Description = strings.Trim(kv.Value.(*ast.BasicLit).Value, `"`)
											case "Signatures":
												if comp, ok := kv.Value.(*ast.CompositeLit); ok {
													for _, signature := range comp.Elts {
														hf.Signatures = append(hf.Signatures, strings.Trim(signature.(*ast.BasicLit).Value, `"`))
													}
												}
											}
										}
									}
								}
							}
							if hf.Name != "" {
								identifier := pkg2NameMapping[pkg.Name]
								if identifier == "" {
									identifier = pkg.Name + "  (" + filepath.Dir(fname) + ")"
								}

								if dslHelpers[identifier] == nil {
									dslHelpers[identifier] = []DSLHelperFunc{}
								}
								dslHelpers[identifier] = append(dslHelpers[identifier], hf)
							}
						}
					}
				}
				return true
			})
		}
	}

	// DSL Helper functions stats
	for pkg, funcs := range dslHelpers {
		fmt.Printf("Found %d DSL Helper functions in package %s\n", len(funcs), pkg)
	}

	// Generate Markdown tables with ## as package name
	if out != "" {
		var sb strings.Builder
		sb.WriteString(`---
title: "Javascript Helper Functions"
description: "Available JS Helper Functions that can be used in global js runtime & protocol specific helpers."
icon: "function"
iconType: "solid"
---


`)

		for pkg, funcs := range dslHelpers {
			sb.WriteString("## " + pkg + "\n\n")
			sb.WriteString("| Name | Description | Signatures |\n")
			sb.WriteString("|------|-------------|------------|\n")
			for _, f := range funcs {
				sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", f.Name, f.Description, strings.Join(f.Signatures, ", ")))
			}
			sb.WriteString("\n")
		}

		if err := os.WriteFile(out, []byte(sb.String()), 0644); err != nil {
			fmt.Println(err)
			return
		}
	}
}
