package util

import (
	"bytes"
	"fmt"
	"strings"

	errorutil "github.com/projectdiscovery/utils/errors"
)

func CreateLink(title string, url string) string {
	return fmt.Sprintf("[%s](%s)", title, url)
}

func MakeBold(text string) string {
	return "**" + text + "**"
}

func CreateTable(headers []string, rows [][]string) (string, error) {
	builder := &bytes.Buffer{}
	headerSize := len(headers)
	if headers == nil || headerSize == 0 {
		return "", errorutil.New("No headers provided")
	}

	builder.WriteString(CreateTableHeader(headers...))

	for _, row := range rows {
		rowSize := len(row)
		if rowSize == headerSize {
			builder.WriteString(CreateTableRow(row...))
		} else if rowSize < headerSize {
			extendedRows := make([]string, headerSize)
			copy(extendedRows, row)
			builder.WriteString(CreateTableRow(extendedRows...))
		} else {
			return "", errorutil.New("Too many columns for the given headers")
		}
	}

	return builder.String(), nil
}

func CreateTableHeader(headers ...string) string {
	headerSize := len(headers)
	if headers == nil || headerSize == 0 {
		return ""
	}

	return CreateTableRow(headers...) +
		"|" + strings.Repeat(" --- |", headerSize) + "\n"
}

func CreateTableRow(elements ...string) string {
	return fmt.Sprintf("| %s |\n", strings.Join(elements, " | "))
}

func CreateHeading3(text string) string {
	return "### " + text + "\n"
}

func CreateHorizontalLine() string {
	// for regular markdown 3 dashes are enough, but for Jira the minimum is 4
	return "----\n"
}
