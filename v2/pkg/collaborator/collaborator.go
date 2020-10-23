package collaborator

import (
	"strings"
	"time"

	"github.com/projectdiscovery/collaborator"
)

const (
	PollSeconds           = 5
	DefaultMaxBufferLimit = 150
)

var DefaultPollInterval time.Duration = time.Second * time.Duration(PollSeconds)

var DefaultCollaborator BurpCollaborator = BurpCollaborator{Collab: collaborator.NewBurpCollaborator()}

type BurpCollaborator struct {
	options *Options // unused
	Collab  *collaborator.BurpCollaborator
}

type Options struct {
	BIID           string
	PollInterval   time.Duration
	MaxBufferLimit int
}

func New(options *Options) *BurpCollaborator {
	collab := collaborator.NewBurpCollaborator()
	collab.AddBIID(options.BIID)
	collab.MaxBufferLimit = options.MaxBufferLimit
	return &BurpCollaborator{Collab: collab, options: options}
}

func (b *BurpCollaborator) Poll() {
	// if no valid biids were provided just return
	if len(b.Collab.BIIDs) > 0 {
		go b.Collab.PollEach(DefaultPollInterval)
	}
}

func (b *BurpCollaborator) Has(s string) bool {
	for _, r := range b.Collab.RespBuffer {
		for i := 0; i < len(r.Responses); i++ {
			// search in dns
			if strings.Contains(r.Responses[i].Data.RawRequestDecoded, s) {
				return true
			}
			// search in http
			if strings.Contains(r.Responses[i].Data.RequestDecoded, s) {
				return true
			}
		}
	}

	return false
}
