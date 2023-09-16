package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"strings"

	filutil "github.com/projectdiscovery/utils/file"
	"github.com/sashabaranov/go-openai"
)

var sysprompt = `
data present after ---raw data--- contains raw data extracted by a parser and contains information about function 
--- example ---
Name: log
Signatures: "log(msg string)"
Signatures: "log(msg map[string]interface{})"
Description: log prints given input to stdout with [JS] prefix for debugging purposes 
--- end example ---
Here Name is name of function , signature[s] is actual function declaration and description is description of function
using this data for every such function generate a abstract implementation of function in javascript along with jsdoc annotations
--- example expected output---
/**
 * log prints given input to stdout with [JS] prefix for debugging purposes
 * log(msg string)
 * log(msg map[string]interface{})
 * @function
 * @param {string} msg - The message to print.
 */
function log(msg) {
    // implemented in go
};
--- instructions ---
ACT as helpful coding assistant and do the same for all functions present in data
`

const userPrompt = `
---raw data---
{{source}}
---new javascript---
`

var (
	dir     string
	key     string
	keyfile string
	out     string
)

func main() {
	flag.StringVar(&dir, "dir", "pkg/js/global", "directory to process")
	flag.StringVar(&key, "key", "", "openai api key")
	flag.StringVar(&keyfile, "keyfile", "", "openai api key file")
	flag.StringVar(&out, "out", "", "output js file with declarations of all global functions")
	flag.Parse()

	finalKey := ""
	if key != "" {
		key = finalKey
	}
	if keyfile != "" && filutil.FileExists(keyfile) {
		data, err := os.ReadFile(keyfile)
		if err != nil {
			log.Fatal(err)
		}
		finalKey = string(data)
	}
	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		finalKey = key
	}

	if finalKey == "" {
		log.Fatal("openai api key is not set")
	}
	llm := openai.NewClient(finalKey)
	var buff bytes.Buffer

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
						if sel.Sel.Name == "RegisterFuncWithSignature" {
							for _, arg := range x.Args {
								if kv, ok := arg.(*ast.CompositeLit); ok {
									for _, elt := range kv.Elts {
										if kv, ok := elt.(*ast.KeyValueExpr); ok {
											key := kv.Key.(*ast.Ident).Name
											switch key {
											case "Name", "Description":
												buff.WriteString(fmt.Sprintf("%s: %s\n", key, strings.Trim(kv.Value.(*ast.BasicLit).Value, `"`)))
											case "Signatures":
												if comp, ok := kv.Value.(*ast.CompositeLit); ok {
													for _, signature := range comp.Elts {
														buff.WriteString(fmt.Sprintf("%s: %s\n", key, signature.(*ast.BasicLit).Value))
													}
												}
											}
										}
									}
								}
							}
							buff.WriteString("\n")
						}
					}
				}
				return true
			})
		}
	}

	fmt.Printf("[+] Scraped %d functions\n\n", strings.Count(buff.String(), "Name:"))
	fmt.Println(buff.String())

	fmt.Printf("[+] Generating jsdoc for all functions\n\n")
	resp, err := llm.CreateChatCompletion(context.TODO(), openai.ChatCompletionRequest{
		Model: "gpt-4",
		Messages: []openai.ChatCompletionMessage{
			{Role: "system", Content: sysprompt},
			{Role: "user", Content: strings.ReplaceAll(userPrompt, "{{source}}", buff.String())},
		},
		Temperature: 0.1,
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	if len(resp.Choices) == 0 {
		fmt.Println("no choices returned")
		return
	}
	data := resp.Choices[0].Message.Content

	fmt.Println(data)

	if out != "" {
		if err := os.WriteFile(out, []byte(data), 0600); err != nil {
			fmt.Println(err)
			return
		}
	}
}
