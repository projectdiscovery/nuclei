package uncover

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/uncover"
	"github.com/projectdiscovery/uncover/sources"
	mapsutil "github.com/projectdiscovery/utils/maps"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// returns csv string of uncover supported agents
func GetUncoverSupportedAgents() string {
	u, _ := uncover.New(&uncover.Options{})
	return strings.Join(u.AllAgents(), ",")
}

// GetTargetsFromUncover returns targets from uncover
func GetTargetsFromUncover(ctx context.Context, outputFormat string, opts *uncover.Options) (chan string, error) {
	u, err := uncover.New(opts)
	if err != nil {
		return nil, err
	}
	resChan, err := u.Execute(ctx)
	if err != nil {
		return nil, err
	}
	outputChan := make(chan string) // buffered channel
	go func() {
		defer close(outputChan)
		for {
			select {
			case <-ctx.Done():
				return
			case res, ok := <-resChan:
				if !ok {
					return
				}
				if res.Error != nil {
					// only log in verbose mode
					gologger.Verbose().Msgf("uncover: %v", res.Error)
					continue
				}
				outputChan <- processUncoverOutput(res, outputFormat)
			}
		}
	}()
	return outputChan, nil
}

// processUncoverOutput returns output string depending on uncover field
func processUncoverOutput(result sources.Result, outputFormat string) string {
	if (result.IP == "" || result.Port == 0) && stringsutil.ContainsAny(outputFormat, "ip", "port") {
		// if ip or port is not present, fallback to using host
		outputFormat = "host"
	}
	replacer := strings.NewReplacer(
		"ip", result.IP,
		"host", result.Host,
		"port", fmt.Sprint(result.Port),
		"url", result.Url,
	)
	return replacer.Replace(outputFormat)
}

// GetUncoverTargetsFromMetadata returns targets from uncover metadata
func GetUncoverTargetsFromMetadata(ctx context.Context, templates []*templates.Template, outputFormat string, opts *uncover.Options) chan string {
	// contains map[engine]queries
	queriesMap := make(map[string][]string)
	for _, template := range templates {
	innerLoop:
		for k, v := range template.Info.Metadata {
			if !strings.HasSuffix(k, "-query") {
				// this is not a query
				// query keys are like shodan-query, fofa-query, etc
				continue innerLoop
			}
			engine := strings.TrimSuffix(k, "-query")
			if queriesMap[engine] == nil {
				queriesMap[engine] = []string{}
			}
			queriesMap[engine] = append(queriesMap[engine], fmt.Sprint(v))
		}
	}
	keys := mapsutil.GetKeys(queriesMap)
	gologger.Info().Msgf("Running uncover queries from template against: %s", strings.Join(keys, ","))
	result := make(chan string, runtime.NumCPU())
	go func() {
		defer close(result)
		// unfortunately uncover doesn't support execution of map[engine]queries
		// if queries are given they are executed against all engines which is not what we want
		// TODO: add support for map[engine]queries in uncover
		// Note below implementation is intentionally sequential to avoid burning all the API keys
		counter := 0

		for eng, queries := range queriesMap {
			// create new uncover options for each engine
			uncoverOpts := &uncover.Options{
				Agents:        []string{eng},
				Queries:       queries,
				Limit:         opts.Limit,
				MaxRetry:      opts.MaxRetry,
				Timeout:       opts.Timeout,
				RateLimit:     opts.RateLimit,
				RateLimitUnit: opts.RateLimitUnit,
			}
			ch, err := GetTargetsFromUncover(ctx, outputFormat, uncoverOpts)
			if err != nil {
				gologger.Error().Msgf("Could not get targets using %v engine from uncover: %s", eng, err)
				return
			}
			for {
				select {
				case <-ctx.Done():
					return
				case res, ok := <-ch:
					if !ok {
						return
					}
					result <- res
					counter++
					if opts.Limit > 0 && counter >= opts.Limit {
						return
					}
				}
			}
		}
	}()
	return result
}
