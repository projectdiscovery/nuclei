package runner

import (
	"slices"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/replay"
)

// replay writes the findings of the loaded templates over a stored corpus
// through the usual output, so -o, -j and the other output options apply.
func (r *Runner) replay(store *loader.Store) error {
	results, err := replay.Replay(r.options.ReplayFile, slices.Concat(store.Templates(), store.Workflows()))
	if err != nil {
		return err
	}
	for _, result := range results {
		if err := r.output.Write(result); err != nil {
			return err
		}
	}
	r.Logger.Info().Msgf("Replayed %s: %d findings", r.options.ReplayFile, len(results))
	return nil
}
