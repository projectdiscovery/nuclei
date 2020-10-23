package collaborator

import (
	"strings"
	"time"

	"github.com/projectdiscovery/collaborator"
)

const (
	DefaultMaxBufferLimit = 150
	DefaultPollInterval   = time.Second * time.Duration(5)
)

var DefaultCollaborator BurpCollaborator = BurpCollaborator{Collab: collaborator.NewBurpCollaborator()}

type BurpCollaborator struct {
	options *Options
	Collab  *collaborator.BurpCollaborator
}

type Options struct {
	BIID           string
	PollInterval   time.Duration
	MaxBufferLimit int
}

func New(options Options) *BurpCollaborator {
	collab := collaborator.NewBurpCollaborator()
	collab.AddBIID(options.BIID)
	collab.MaxBufferLimit = options.MaxBufferLimit
	return &BurpCollaborator{Collab: collab}
}

func (b *BurpCollaborator) Poll() {
	// if no valid biids were provided just return
	if len(b.Collab.BIIDs) > 0 {
		go b.Collab.PollEach(DefaultPollInterval)
	}
}

func (b *BurpCollaborator) Has(s string) bool {
	for _, r := range b.Collab.RespBuffer {
		for _, rr := range r.Responses {
			// search in dns
			if strings.Contains(rr.Data.RawRequestDecoded, s) {
				return true
			}
			// search in http
			if strings.Contains(rr.Data.RequestDecoded, s) {
				return true
			}
		}
	}

	return false
}
