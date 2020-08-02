package progress

type NoOpProgress struct{}

func (p *NoOpProgress) InitProgressbar(hostCount int64, templateCount int, requestCount int64) {}
func (p *NoOpProgress) AddToTotal(delta int64)                                                 {}
func (p *NoOpProgress) Update()                                                                {}
func (p *NoOpProgress) Drop(count int64)                                                       {}
func (p *NoOpProgress) Wait()                                                                  {}
