package format

type ResultFormatter interface {
	MakeBold(text string) string
	CreateCodeBlock(title string, content string, language string) string
	CreateTable(headers []string, rows [][]string) (string, error)
	CreateLink(title string, url string) string
	CreateHorizontalLine() string
}
