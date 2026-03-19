package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
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
	output          output.Writer
	interactsh      *interactsh.Client
	options         *types.Options
	progress        progress.Progress
	catalog         catalog.Catalog
	loader          *loader.Loader
	store           *loader.Store
	reportingClient reporting.Client
	browser         *engine.Browser
	ratelimiter     *ratelimit.Limiter
	hostErrors      hosterrorscache.CacheInterface
	resumeCfg       *types.ResumeConfig
	pprofServer     *http.Server
	executerOpts    protocols.ExecuterOptions
}
