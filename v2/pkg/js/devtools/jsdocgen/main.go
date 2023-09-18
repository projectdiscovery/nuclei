package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"

	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	openai "github.com/sashabaranov/go-openai"
)

var (
	dir     string
	key     string
	keyfile string
)

const sysPrompt = `
you are helpful coding assistant responsible for generating javascript file with js annotations for nuclei from a 'corrupted' javascript file.
--- example input ---
/** @module mymodule */

class TestClass {
	function Execute(path){
		return []string , error
	}
}

function ListTests(){
	return Testcases , error
}

module.exports = {
	TestClass: TestClass,
	ListTests: ListTests,
}
--- end example ---
--- example output ---
/** @module mymodule */

/**
 * @class
 * @classdesc TestClass is a class used for testing purposes
 */
class TestClass {
	/**
	@method
	@description Execute executes the test and returns the results
	@param {string} path - The path to execute the test on.
	@returns {string[]} - The results of the test in an array.
	@throws {error} - The error encountered during test execution.
	@example
	let m = require('nuclei/mymodule');
	let c = m.TestClass();
	let results = c.Execute('/tmp');
	*/
	function Execute(path){
		// implemented in go
	};
};

/**
 * @function
 * @description ListTests lists all the tests available
 * @typedef {Object} Testcases
 * @returns {Testcases} - The testcases object containing all the tests.
 * @throws {error} - The error encountered during test listing.
 * @example
 * let m = require('nuclei/mymodule'); 
 * let tests = m.ListTests();
 */
function ListTests(){
	// implemented in go
};

 module.exports = {
	TestClass: TestClass,
	ListTests: ListTests,
}
--- end example ---
--- instructions ---
1. DONOT ADD ANY NEW Annotation (@) Other than those already mentioned in above example
2. All Function/Class/Method body should be empty with comment 'implemented in go'
3. ALL MODULE IMPORT PATHS SHOULD BE 'nuclei/<module name>'
4. If any function returns a unknown type then always define it using @typedef and then use it in @returns
--- end instructions ---
`

const userPrompt = `
---original javascript---
{{source}}
---new javascript---
`

// doclint is automatic javascript documentation linter for nuclei
// it uses LLM to autocomplete the generated js code to proper JSDOC notation
func main() {
	flag.StringVar(&dir, "dir", "", "directory to process")
	flag.StringVar(&key, "key", "", "openai api key")
	flag.StringVar(&keyfile, "keyfile", "", "openai api key file")
	flag.Parse()
	log.SetFlags(0)

	if dir == "" {
		log.Fatal("dir is not set")
	}
	finalKey := ""
	if key != "" {
		key = finalKey
	}
	if keyfile != "" && fileutil.FileExists(keyfile) {
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

	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if !d.IsDir() && filepath.Ext(path) == ".js" {
			log.Printf("Processing %s", path)
			if err := updateDocsWithLLM(llm, path); err != nil {
				log.Printf("Error processing %s: %s", path, err)
			} else {
				log.Printf("Processed %s", path)
			}
		}
		return nil
	})
}

// updateDocsWithLLM updates the documentation of a javascript file
func updateDocsWithLLM(llm *openai.Client, path string) error {
	// read the file
	bin, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	resp, err := llm.CreateChatCompletion(context.TODO(), openai.ChatCompletionRequest{
		Model: "gpt-4",
		Messages: []openai.ChatCompletionMessage{
			{Role: "system", Content: sysPrompt},
			{Role: "user", Content: strings.ReplaceAll(userPrompt, "{{source}}", string(bin))},
		},
		Temperature: 0.1,
	})
	if err != nil {
		return err
	}
	if len(resp.Choices) == 0 {
		return errorutil.New("no choices returned")
	}
	data := resp.Choices[0].Message.Content
	return os.WriteFile(path, []byte(data), 0644)
}
