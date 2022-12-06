package trustoracle

import (
	"bufio"
	"bytes"
	"fmt"
	"os"

	fileutil "github.com/projectdiscovery/utils/file"
)

// Oracle decides which code templates are allowed to run
type Oracle struct {
	db   string
	seen map[string]struct{}
}

// NewOracle creates a new oracle instance
func NewOracle() (*Oracle, error) {
	seen := make(map[string]struct{})
	return &Oracle{seen: seen}, nil
}

// NewOracle from a text based list of templates
func NewOracleWithDb(db string) (*Oracle, error) {
	seen := make(map[string]struct{})
	if db != "" && fileutil.FileExists(db) {
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

// HasSeen tells if the oracle has previously seen the item
func (o *Oracle) HasSeen(item string) bool {
	_, ok := o.seen[item]
	return ok
}

// MarkSeen tells the oracle to mark the item as seen and trusted - currently not used
func (o *Oracle) MarkSeen(items ...string) {
	for _, item := range items {
		o.seen[item] = struct{}{}
	}
}

// Save overwrite the initial db with the new oracle insertions
func (o *Oracle) Save() error {
	var list bytes.Buffer
	for s := range o.seen {
		list.WriteString(fmt.Sprintln(s))
	}
	return os.WriteFile(o.db, list.Bytes(), 0600)
}
