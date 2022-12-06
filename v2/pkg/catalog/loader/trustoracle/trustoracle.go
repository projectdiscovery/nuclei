package trustoracle

import (
	"bufio"
	"bytes"
	"fmt"
	"os"

	fileutil "github.com/projectdiscovery/utils/file"
)

type Oracle struct {
	db   string
	seen map[string]struct{}
}

func NewOracle(db string) (*Oracle, error) {
	seen := make(map[string]struct{})
	if fileutil.FileExists(db) {
		file, err := os.Open(db)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			item := scanner.Text()
			seen[item] = struct{}{}
		}
	}

	return &Oracle{db: db, seen: seen}, nil
}

func (o *Oracle) HasSeen(item string) bool {
	_, ok := o.seen[item]
	return ok
}

func (o *Oracle) MarkSeen(items ...string) {
	for _, item := range items {
		o.seen[item] = struct{}{}
	}
}

func (o *Oracle) Save() error {
	var list bytes.Buffer
	for s := range o.seen {
		list.WriteString(fmt.Sprintln(s))
	}
	return os.WriteFile(o.db, list.Bytes(), 0600)
}
