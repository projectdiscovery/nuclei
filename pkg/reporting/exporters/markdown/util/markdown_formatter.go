package util

import (
	"fmt"
	"strings"
)

type MarkdownFormatter struct{}

func (markdownFormatter MarkdownFormatter) MakeBold(text string) string {
	return MakeBold(text)
}

func (markdownFormatter MarkdownFormatter) CreateCodeBlock(title string, content string, language string) string {
	escapedContent := escapeCodeBlockMarkdown(content)
	return fmt.Sprintf("\n%s\n```%s\n%s\n```\n", markdownFormatter.MakeBold(title), language, escapedContent)
}

func (markdownFormatter MarkdownFormatter) CreateTable(headers []string, rows [][]string) (string, error) {
	return CreateTable(headers, rows)
}

func (markdownFormatter MarkdownFormatter) CreateLink(title string, url string) string {
	return CreateLink(title, url)
}

func (markdownFormatter MarkdownFormatter) CreateHorizontalLine() string {
	return CreateHorizontalLine()
}

// escapeCodeBlockMarkdown only escapes the bare minimum characters needed
// for code blocks and other sections where readability is important
//
// For content inside code blocks, we only need to escape backticks
// and backslashes to prevent breaking out
func escapeCodeBlockMarkdown(text string) string {
	minimalChars := []string{
		"\\", "`",
	}

	result := text
	for _, char := range minimalChars {
		result = strings.ReplaceAll(result, char, "\\"+char)
	}
	return result
}
