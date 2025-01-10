package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/exp/maps"
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
	"flow":       "Template Flow",
}

var preferredOrder = []string{"Javascript Runtime", "Template Flow", "Code Protocol", "JavaScript Protocol"}

func main() {
	flag.StringVar(&dir, "dir", "pkg/", "directory to process")
	flag.StringVar(&out, "out", "", "output markdown file with helper file declarations")
	flag.Parse()

	dirList := []string{}

	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			dirList = append(dirList, path)
		}
		return nil
	}); err != nil {
		panic(err)
	}

	dslHelpers := map[string][]DSLHelperFunc{}

	//for _, pkg := range pkgs {
	for _, dir := range dirList {
		fset := token.NewFileSet()
		list, err := os.ReadDir(dir)
		if err != nil {
			fmt.Println(err)
			return
		}

		for _, f := range list {
			if f.IsDir() {
				continue
			}
			if !strings.HasSuffix(f.Name(), ".go") {
				continue
			}

			astFile, err := parser.ParseFile(fset, filepath.Join(dir, f.Name()), nil, parser.AllErrors|parser.SkipObjectResolution)
			if err != nil {
				fmt.Println(err)
				return
			}

			ast.Inspect(astFile, func(n ast.Node) bool {
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
								identifier := pkg2NameMapping[astFile.Name.Name]
								if identifier == "" {
									identifier = astFile.Name.Name + "  (" + dir + ")"
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

		actualKeys := maps.Keys(dslHelpers)
		sort.Slice(actualKeys, func(i, j int) bool {
			for _, preferredKey := range preferredOrder {
				if actualKeys[i] == preferredKey {
					return true
				}
				if actualKeys[j] == preferredKey {
					return false
				}
			}
			return actualKeys[i] < actualKeys[j]
		})

		for _, v := range actualKeys {
			pkg := v
			funcs := dslHelpers[pkg]
			sb.WriteString("## " + pkg + "\n\n")
			sb.WriteString("| Name | Description | Signatures |\n")
			sb.WriteString("|------|-------------|------------|\n")
			for _, f := range funcs {
				sigSlice := []string{}
				for _, sig := range f.Signatures {
					sigSlice = append(sigSlice, "`"+sig+"`")
				}
				sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", f.Name, f.Description, strings.Join(sigSlice, ", ")))
			}
			sb.WriteString("\n")
		}

		if err := os.WriteFile(out, []byte(sb.String()), 0644); err != nil {
			fmt.Println(err)
			return
		}
	}
}
