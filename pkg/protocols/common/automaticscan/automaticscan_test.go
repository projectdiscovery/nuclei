package automaticscan

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestNormalizeAppName(t *testing.T) {
	appName := normalizeAppName("JBoss")
	require.Equal(t, "jboss", appName, "could not get normalized name")

	appName = normalizeAppName("JBoss:2.3.5")
	require.Equal(t, "jboss", appName, "could not get normalized name")
}

// countingExecuter counts the runs of a detection template.
type countingExecuter struct {
	runs atomic.Int32
}

func (c *countingExecuter) Compile() error { return nil }
func (c *countingExecuter) Requests() int  { return 1 }
func (c *countingExecuter) Execute(*scan.ScanContext) (bool, error) {
	c.runs.Add(1)

	return false, nil
}
func (c *countingExecuter) ExecuteWithResults(*scan.ScanContext) ([]*output.ResultEvent, error) {
	c.runs.Add(1)

	return nil, nil
}

// A -c or -bs below 1 must not make the service fail or dereference a nil
// pool; it runs one task at a time.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults
func TestServiceRunsWithConcurrencyBelowOne(t *testing.T) {
	for _, value := range []int{0, -1} {
		t.Run("-c="+strconv.Itoa(value), func(t *testing.T) {
			executer := &countingExecuter{}
			service := &Service{
				opts:          &protocols.ExecutorOptions{Options: &types.Options{TemplateThreads: value}},
				techTemplates: []*templates.Template{{ID: "tech-detect", Executer: executer}},
			}

			input := contextargs.NewMetaInput()
			input.Input = "http://127.0.0.1"

			require.NotPanics(t, func() { service.getTagsUsingDetectionTemplates(t.Context(), input) })
			require.EqualValues(t, 1, executer.runs.Load(), "the detection template runs once")
		})

		t.Run("-bs="+strconv.Itoa(value), func(t *testing.T) {
			service := &Service{
				opts:   &protocols.ExecutorOptions{Options: &types.Options{BulkSize: value}},
				target: provider.NewSimpleInputProvider(),
			}

			require.NoError(t, service.Execute(t.Context()))
		})
	}
}
