package protocolstate

import (
	"github.com/projectdiscovery/utils/memoize"
)

// memoizerMaxSize is the process-wide @memo helper cache capacity.
// Keys are xxhash uint64s of the arg string; values are the helper results.
const memoizerMaxSize = 10_000

var Memoizer *memoize.Memoizer

func init() {
	var err error
	Memoizer, err = memoize.New(memoize.WithMaxSize(memoizerMaxSize))
	if err != nil {
		panic(err)
	}
}
