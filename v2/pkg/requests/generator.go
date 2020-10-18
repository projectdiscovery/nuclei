package requests

import (
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v2/pkg/generators"
)

type GeneratorState int

const (
	fifteen                = 15
	initial GeneratorState = iota
	running
	done
)

type Generator struct {
	sync.RWMutex
	positionPath          int
	positionRaw           int
	gchan                 chan map[string]interface{}
	currentGeneratorValue map[string]interface{}
	state                 GeneratorState
}

type GeneratorFSM struct {
	sync.RWMutex
	payloads     map[string]interface{}
	basePayloads map[string][]string
	generator    func(payloads map[string][]string) (out chan map[string]interface{})
	Generators   map[string]*Generator
	Type         generators.Type
	Paths        []string
	Raws         []string
}

func NewGeneratorFSM(typ generators.Type, payloads map[string]interface{}, paths, raws []string) *GeneratorFSM {
	var gsfm GeneratorFSM
	gsfm.payloads = payloads
	gsfm.Paths = paths
	gsfm.Raws = raws
	gsfm.Type = typ

	if len(gsfm.payloads) > 0 {
		// load payloads if not already done
		if gsfm.basePayloads == nil {
			gsfm.basePayloads = generators.LoadPayloads(gsfm.payloads)
		}

		generatorFunc := generators.SniperGenerator

		switch typ {
		case generators.PitchFork:
			generatorFunc = generators.PitchforkGenerator
		case generators.ClusterBomb:
			generatorFunc = generators.ClusterbombGenerator
		case generators.Sniper:
			generatorFunc = generators.SniperGenerator
		}

		gsfm.generator = generatorFunc
	}

	gsfm.Generators = make(map[string]*Generator)

	return &gsfm
}

func (gfsm *GeneratorFSM) Add(key string) {
	gfsm.Lock()
	defer gfsm.Unlock()

	if _, ok := gfsm.Generators[key]; !ok {
		gfsm.Generators[key] = &Generator{state: initial}
	}
}

func (gfsm *GeneratorFSM) Has(key string) bool {
	gfsm.RLock()
	defer gfsm.RUnlock()

	_, ok := gfsm.Generators[key]

	return ok
}

func (gfsm *GeneratorFSM) Delete(key string) {
	gfsm.Lock()
	defer gfsm.Unlock()

	delete(gfsm.Generators, key)
}

func (gfsm *GeneratorFSM) ReadOne(key string) {
	gfsm.RLock()
	defer gfsm.RUnlock()
	g, ok := gfsm.Generators[key]

	if !ok {
		return
	}

	for afterCh := time.After(fifteen * time.Second); ; {
		select {
		// got a value
		case curGenValue, ok := <-g.gchan:
			if !ok {
				g.Lock()
				g.gchan = nil
				g.state = done
				g.currentGeneratorValue = nil
				g.Unlock()

				return
			}

			g.currentGeneratorValue = curGenValue

			return
		// timeout
		case <-afterCh:
			g.Lock()
			g.gchan = nil
			g.state = done
			g.Unlock()

			return
		}
	}
}

func (gfsm *GeneratorFSM) InitOrSkip(key string) {
	gfsm.RLock()
	defer gfsm.RUnlock()

	g, ok := gfsm.Generators[key]
	if !ok {
		return
	}

	if len(gfsm.payloads) > 0 {
		g.Lock()
		defer g.Unlock()

		if g.gchan == nil {
			g.gchan = gfsm.generator(gfsm.basePayloads)
			g.state = running
		}
	}
}

func (gfsm *GeneratorFSM) Value(key string) map[string]interface{} {
	gfsm.RLock()
	defer gfsm.RUnlock()

	g, ok := gfsm.Generators[key]
	if !ok {
		return nil
	}

	return g.currentGeneratorValue
}

func (gfsm *GeneratorFSM) Next(key string) bool {
	gfsm.RLock()
	defer gfsm.RUnlock()

	g, ok := gfsm.Generators[key]
	if !ok {
		return false
	}

	if g.positionPath+g.positionRaw >= len(gfsm.Paths)+len(gfsm.Raws) {
		return false
	}

	return true
}

func (gfsm *GeneratorFSM) Position(key string) int {
	gfsm.RLock()
	defer gfsm.RUnlock()

	g, ok := gfsm.Generators[key]
	if !ok {
		return 0
	}

	return g.positionPath + g.positionRaw
}

func (gfsm *GeneratorFSM) Reset(key string) {
	gfsm.Lock()
	defer gfsm.Unlock()

	if !gfsm.Has(key) {
		gfsm.Add(key)
	}

	g, ok := gfsm.Generators[key]
	if !ok {
		return
	}

	g.positionPath = 0
	g.positionRaw = 0
}

func (gfsm *GeneratorFSM) Current(key string) string {
	gfsm.RLock()
	defer gfsm.RUnlock()

	g, ok := gfsm.Generators[key]
	if !ok {
		return ""
	}

	if g.positionPath < len(gfsm.Paths) && len(gfsm.Paths) != 0 {
		return gfsm.Paths[g.positionPath]
	}

	return gfsm.Raws[g.positionRaw]
}
func (gfsm *GeneratorFSM) Total() int {
	estimatedRequestsWithPayload := 0
	if len(gfsm.basePayloads) > 0 {
		switch gfsm.Type {
		case generators.Sniper:
			for _, kv := range gfsm.basePayloads {
				estimatedRequestsWithPayload += len(kv)
			}
		case generators.PitchFork:
			// Positional so it's equal to the length of one list
			for _, kv := range gfsm.basePayloads {
				estimatedRequestsWithPayload += len(kv)
				break
			}
		case generators.ClusterBomb:
			// Total of combinations => rule of product
			prod := 1
			for _, kv := range gfsm.basePayloads {
				prod *= len(kv)
			}
			estimatedRequestsWithPayload += prod
		}
	}

	return len(gfsm.Paths) + len(gfsm.Raws) + estimatedRequestsWithPayload
}

func (gfsm *GeneratorFSM) Increment(key string) {
	gfsm.Lock()
	defer gfsm.Unlock()

	g, ok := gfsm.Generators[key]
	if !ok {
		return
	}

	if len(gfsm.Paths) > 0 && g.positionPath < len(gfsm.Paths) {
		g.positionPath++
		return
	}

	if len(gfsm.Raws) > 0 && g.positionRaw < len(gfsm.Raws) {
		// if we have payloads increment only when the generators are done
		if g.gchan == nil {
			g.state = done
			g.positionRaw++
		}
	}
}
