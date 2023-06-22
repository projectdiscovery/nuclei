package util

import (
	"fmt"
)

type MarkdownFormatter struct{}

func (markdownFormatter MarkdownFormatter) MakeBold(text string) string {
	return MakeBold(text)
}

func (markdownFormatter MarkdownFormatter) CreateCodeBlock(title string, content string, language string) string {
	return fmt.Sprintf("\n%s\n```%s\n%s\n```\n", markdownFormatter.MakeBold(title), language, content)
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
