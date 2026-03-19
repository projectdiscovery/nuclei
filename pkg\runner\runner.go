package runner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/internal/runner/nucleicloud"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/core/inputs"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/uncover"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/excludematchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/headless/engine"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/stats"
	"github.com/projectdiscovery/ratelimit"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	permissionutil "github.com/projectdiscovery/utils/permission"
	updateutils "github.com/projectdiscovery/utils/update"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	output            output.Writer
	interactsh        *interactsh.Client
	options           *types.Options
	progress          progress.Progress
	catalog           catalog.Catalog
	loader            *loader.Loader
	store             *loader.Store
	reportingClient   reporting.Client
	browser           *engine.Browser
	ratelimiter       *ratelimit.Limiter
	hostErrors        hosterrorscache.CacheInterface
	resumeCfg         *types.ResumeConfig
	pprofServer       *http.Server
	executerOpts      protocols.ExecuterOptions
}

// New creates a new runner
func New(options *types.Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}
	// ... existing initialization
	return runner, nil
}

// RunEnumeration sets up the input layer for awaiting
// and starts the execution
func (r *Runner) RunEnumeration() error {
	// ... existing code
	
	// Ensure secrets are pre-fetched synchronously before scanning begins
	// This fixes the race condition where templates execute before
	// the secret-file template finishes
	if r.executerOpts.AuthProvider != nil {
		if err := r.executerOpts.AuthProvider.PreFetchSecrets(); err != nil {
			gologger.Warning().Msgf("Could not pre-fetch secrets: %s\n", err)
		}
	}
	
	// ... rest of execution
}
