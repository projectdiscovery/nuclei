package runner

import (
	"sync"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/core/techfilter"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
)

// tagsFor is filled lazily from the template execution goroutines. Run it under
// -race to catch the concurrent map access that used to crash whole scans.
func TestTechReachabilityIndexConcurrentTagsFor(t *testing.T) {
	idx := &techReachabilityIndex{
		byInput:   map[string]techfilter.HostProfile{},
		boundTags: map[string][]string{},
	}

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 64; j++ {
				tpl := &templates.Template{ID: string(rune('a' + (i+j)%26))}
				_ = idx.tagsFor(tpl)
				_ = idx.Allow(tpl, &contextargs.MetaInput{Input: "http://x/"})
			}
		}(i)
	}
	wg.Wait()
}
