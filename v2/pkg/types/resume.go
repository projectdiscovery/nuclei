package types

// Default resume file
const DefaultResumeFile = "resume.cfg"

// ResumeCfg contains the scan progression
type ResumeCfg struct {
	TemplatesResumeFrom      map[string]string `json:"resumeFrom"`
	TemplatesResumeFromIndex map[string]uint32 `json:"resumeFromIndex"`
	TemplatesCurrent         map[string]string `json:"-"`
	TemplatesCurrentIndex    map[string]uint32 `json:"-"`
}

// NewResumeCfg creates a new scan progression structure
func NewResumeCfg() *ResumeCfg {
	return &ResumeCfg{
		TemplatesResumeFrom:      make(map[string]string),
		TemplatesResumeFromIndex: make(map[string]uint32),
		TemplatesCurrent:         make(map[string]string),
		TemplatesCurrentIndex:    make(map[string]uint32),
	}
}

// Clone the resume structure
func (resumeCfg *ResumeCfg) Clone() ResumeCfg {
	return ResumeCfg{
		TemplatesResumeFrom:      resumeCfg.TemplatesResumeFrom,
		TemplatesResumeFromIndex: resumeCfg.TemplatesResumeFromIndex,
		TemplatesCurrent:         resumeCfg.TemplatesCurrent,
		TemplatesCurrentIndex:    resumeCfg.TemplatesCurrentIndex,
	}
}
