package collaborator

import (
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/collaborator"
)

var (
	// PollSeconds is the seconds to poll at.
	PollSeconds = 5
	// DefaultMaxBufferLimit is the default request buffer limit
	DefaultMaxBufferLimit = 150
	// DefaultPollInterval is the default poll interval for burp collabortor polling.
	DefaultPollInterval time.Duration = time.Second * time.Duration(PollSeconds)
	// DefaultCollaborator is the default burp collaborator instance
	DefaultCollaborator = &Collaborator{Collab: collaborator.NewBurpCollaborator()}
)

// Collaborator is a client for recording burp collaborator interactions
type Collaborator struct {
	sync.RWMutex
	options *Options // unused
	Collab  *collaborator.BurpCollaborator
}

// Options contains configuration options for collaborator client
type Options struct {
	BIID           string
	PollInterval   time.Duration
	MaxBufferLimit int
}

// New creates a new collaborator client
func New(options *Options) *Collaborator {
	collab := collaborator.NewBurpCollaborator()
	collab.AddBIID(options.BIID)
	collab.MaxBufferLimit = options.MaxBufferLimit
	return &Collaborator{Collab: collab, options: options}
}

// Poll initiates collaborator polling if any BIIDs were provided
func (b *Collaborator) Poll() {
	// if no valid biids were provided just return
	if len(b.Collab.BIIDs) > 0 {
		go b.Collab.PollEach(DefaultPollInterval)
	}
}

// Has checks if a collabrator hit was found for a URL
func (b *Collaborator) Has(s string) bool {
	for _, r := range b.Collab.RespBuffer {
		for i := 0; i < len(r.Responses); i++ {
			// search in dns - http - smtp
			b.RLock()
			found := strings.Contains(r.Responses[i].Data.RawRequestDecoded, s) ||
				strings.Contains(r.Responses[i].Data.RequestDecoded, s) ||
				strings.Contains(r.Responses[i].Data.MessageDecoded, s)
			b.RUnlock()

			if found {
				b.Lock()
				r.Responses = append(r.Responses[:i], r.Responses[i+1:]...)
				b.Unlock()
				return true
			}
		}
	}
	return false
}
