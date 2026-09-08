package templates

import (
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type countingCatalog struct {
	reads atomic.Int32
}

func (c *countingCatalog) OpenFile(string) (io.ReadCloser, error) {
	c.reads.Add(1)
	time.Sleep(25 * time.Millisecond)
	return io.NopCloser(strings.NewReader("id: concurrent-parse\ninfo:\n  name: Concurrent parse\n  author: pd\n  severity: info\n")), nil
}

func (*countingCatalog) GetTemplatePath(string) ([]string, error) { return nil, nil }
func (*countingCatalog) GetTemplatesPath([]string) ([]string, map[string]error) {
	return nil, nil
}
func (*countingCatalog) ResolvePath(string, string) (string, error) { return "", nil }

func TestParseTemplateCoalescesConcurrentCacheMisses(t *testing.T) {
	const callers = 20
	cache := NewCache()
	catalog := &countingCatalog{}
	start := make(chan struct{})
	errs := make(chan error, callers)
	var wg sync.WaitGroup

	for range callers {
		parser := NewParserWithParsedCache(cache)
		wg.Add(1)
		go func(parser *Parser) {
			defer wg.Done()
			<-start
			_, err := parser.ParseTemplate("concurrent.yaml", catalog)
			errs <- err
		}(parser)
	}

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
	require.EqualValues(t, 1, catalog.reads.Load(), "one shared cache miss should read and parse the template once")
}
