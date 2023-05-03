package types

import (
	"fmt"
	"math"
	"path/filepath"
	"sync"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/rs/xid"
)

// Default resume file
const DefaultResumeFileName = "resume-%s.cfg"

func DefaultResumeFilePath() string {
	configDir := config.DefaultConfig.GetConfigDir()
	resumeFile := filepath.Join(configDir, fmt.Sprintf(DefaultResumeFileName, xid.New().String()))
	return resumeFile
}

// ResumeCfg contains the scan progression
type ResumeCfg struct {
	sync.RWMutex
	ResumeFrom map[string]*ResumeInfo `json:"resumeFrom"`
	Current    map[string]*ResumeInfo `json:"-"`
}

type ResumeInfo struct {
	sync.RWMutex
	Completed bool                `json:"completed"`
	InFlight  map[uint32]struct{} `json:"inFlight"`
	SkipUnder uint32              `json:"-"`
	Repeat    map[uint32]struct{} `json:"-"`
	DoAbove   uint32              `json:"-"`
}

// Clone the ResumeInfo structure
func (resumeInfo *ResumeInfo) Clone() *ResumeInfo {
	resumeInfo.Lock()
	defer resumeInfo.Unlock()

	inFlight := make(map[uint32]struct{})
	for u := range resumeInfo.InFlight {
		inFlight[u] = struct{}{}
	}
	repeat := make(map[uint32]struct{})
	for u := range resumeInfo.Repeat {
		repeat[u] = struct{}{}
	}

	return &ResumeInfo{
		Completed: resumeInfo.Completed,
		InFlight:  inFlight,
		SkipUnder: resumeInfo.SkipUnder,
		Repeat:    repeat,
		DoAbove:   resumeInfo.DoAbove,
	}
}

// NewResumeCfg creates a new scan progression structure
func NewResumeCfg() *ResumeCfg {
	return &ResumeCfg{
		ResumeFrom: make(map[string]*ResumeInfo),
		Current:    make(map[string]*ResumeInfo),
	}
}

// Clone the resume structure
func (resumeCfg *ResumeCfg) Clone() *ResumeCfg {
	resumeCfg.Lock()
	defer resumeCfg.Unlock()

	resumeFrom := make(map[string]*ResumeInfo)
	for id, resumeInfo := range resumeCfg.ResumeFrom {
		resumeFrom[id] = resumeInfo.Clone()
	}
	current := make(map[string]*ResumeInfo)
	for id, resumeInfo := range resumeCfg.Current {
		current[id] = resumeInfo.Clone()
	}

	return &ResumeCfg{
		ResumeFrom: resumeFrom,
		Current:    current,
	}
}

// Clone the resume structure
func (resumeCfg *ResumeCfg) Compile() {
	resumeCfg.Lock()
	defer resumeCfg.Unlock()

	for _, resumeInfo := range resumeCfg.ResumeFrom {
		if resumeInfo.Completed && len(resumeInfo.InFlight) > 0 {
			resumeInfo.InFlight = make(map[uint32]struct{})
		}
		min := uint32(math.MaxUint32)
		max := uint32(0)
		for index := range resumeInfo.InFlight {
			if index < min {
				min = index
			}
			if index > max {
				max = index
			}
		}
		// maybe redundant but ensures we track the indexes to be repeated
		resumeInfo.Repeat = map[uint32]struct{}{}
		for index := range resumeInfo.InFlight {
			resumeInfo.Repeat[index] = struct{}{}
		}
		resumeInfo.SkipUnder = min
		resumeInfo.DoAbove = max
	}
}
