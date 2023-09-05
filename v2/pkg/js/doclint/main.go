package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"

	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	openai "github.com/sashabaranov/go-openai"
)

var (
	dir     string
	key     string
	keyfile string
)

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
			{Role: "system", Content: "Act as helpful assistant and update below js code with proper documentation so that it can be parsed by jsdoc. Note: in javascript code if any function/method return 'error' remove it as errors are thrown not returned"},
			{Role: "user", Content: string(bin)},
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
