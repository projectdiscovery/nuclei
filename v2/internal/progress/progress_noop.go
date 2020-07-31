package progress

import "github.com/vbauerster/mpb/v5"

type NoOpProgress struct{}

func (p *NoOpProgress) setupProgressbar(name string, total int64, priority int) *mpb.Bar       { return nil }
func (p *NoOpProgress) InitProgressbar(hostCount int64, templateCount int, requestCount int64) {}
func (p *NoOpProgress) AddToTotal(delta int64)                                                 {}
func (p *NoOpProgress) Update()                                                                {}
func (p *NoOpProgress) render()                                                                {}
func (p *NoOpProgress) Drop(count int64)                                                       {}
func (p *NoOpProgress) Wait()                                                                  {}
func (p *NoOpProgress) StartStdCapture()                                                       {}
func (p *NoOpProgress) StopStdCapture()                                                        {}
