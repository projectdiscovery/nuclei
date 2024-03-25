package core

import syncutil "github.com/projectdiscovery/utils/sync"

// todo: this is just an empty wrapper => remove?

// InputWorkPool is a work pool per-input
type InputWorkPool struct {
	WaitGroup *syncutil.AdaptiveWaitGroup
}

func (iwp *InputWorkPool) Alter(size int) {
	iwp.WaitGroup.Resize(size)
}
