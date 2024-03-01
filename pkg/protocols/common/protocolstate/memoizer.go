package protocolstate

import (
	"github.com/projectdiscovery/utils/memoize"
)

var Memoizer *memoize.Memoizer

func init() {
	var err error
	Memoizer, err = memoize.New(memoize.WithMaxSize(1500))
	if err != nil {
		panic(err)
	}
}
