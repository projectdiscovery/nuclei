package input

// TODO: Decide the location for this file

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	ucRunner "github.com/projectdiscovery/uncover/runner"
	"github.com/projectdiscovery/uncover/uncover"
	"github.com/projectdiscovery/uncover/uncover/agent/censys"
	"github.com/projectdiscovery/uncover/uncover/agent/fofa"
	"github.com/projectdiscovery/uncover/uncover/agent/hunter"
	"github.com/projectdiscovery/uncover/uncover/agent/quake"
	"github.com/projectdiscovery/uncover/uncover/agent/shodan"
	"github.com/projectdiscovery/uncover/uncover/agent/shodanidb"
	"github.com/projectdiscovery/uncover/uncover/agent/zoomeye"
)

func GetTargetsFromUncover(delay, limit int, engine, query []string) (chan string, error) {

	uncoverOptions := &ucRunner.Options{
		Provider: &ucRunner.Provider{},
		Delay:    delay,
		Limit:    limit,
		Query:    query,
		Engine:   engine,
	}
	err := loadProvidersFromEnv(uncoverOptions)
	if err != nil {
		return nil, err
	}
	var censysRateLimiter, fofaRateLimiter, shodanRateLimiter, shodanIdbRateLimiter, quakeRatelimiter, hunterRatelimiter, zoomeyeRatelimiter *ratelimit.Limiter
	if uncoverOptions.Delay > 0 {
		censysRateLimiter = ratelimit.New(context.Background(), 1, time.Duration(uncoverOptions.Delay))
		fofaRateLimiter = ratelimit.New(context.Background(), 1, time.Duration(uncoverOptions.Delay))
		shodanRateLimiter = ratelimit.New(context.Background(), 1, time.Duration(uncoverOptions.Delay))
		shodanIdbRateLimiter = ratelimit.New(context.Background(), 1, time.Duration(uncoverOptions.Delay))
		quakeRatelimiter = ratelimit.New(context.Background(), 1, time.Duration(uncoverOptions.Delay))
		hunterRatelimiter = ratelimit.New(context.Background(), 1, time.Duration(uncoverOptions.Delay))
		zoomeyeRatelimiter = ratelimit.New(context.Background(), 1, time.Duration(uncoverOptions.Delay))
	} else {
		censysRateLimiter = ratelimit.NewUnlimited(context.Background())
		fofaRateLimiter = ratelimit.NewUnlimited(context.Background())
		shodanRateLimiter = ratelimit.NewUnlimited(context.Background())
		shodanIdbRateLimiter = ratelimit.NewUnlimited(context.Background())
		quakeRatelimiter = ratelimit.NewUnlimited(context.Background())
		hunterRatelimiter = ratelimit.NewUnlimited(context.Background())
		zoomeyeRatelimiter = ratelimit.NewUnlimited(context.Background())
	}
	var agents []uncover.Agent
	// declare clients
	for _, engine := range uncoverOptions.Engine {
		var (
			agent uncover.Agent
			err   error
		)
		switch engine {
		case "shodan":
			agent, err = shodan.NewWithOptions(&uncover.AgentOptions{RateLimiter: shodanRateLimiter})
		case "censys":
			agent, err = censys.NewWithOptions(&uncover.AgentOptions{RateLimiter: censysRateLimiter})
		case "fofa":
			agent, err = fofa.NewWithOptions(&uncover.AgentOptions{RateLimiter: fofaRateLimiter})
		case "shodan-idb":
			agent, err = shodanidb.NewWithOptions(&uncover.AgentOptions{RateLimiter: shodanIdbRateLimiter})
		case "quake":
			agent, err = quake.NewWithOptions(&uncover.AgentOptions{RateLimiter: quakeRatelimiter})
		case "hunter":
			agent, err = hunter.NewWithOptions(&uncover.AgentOptions{RateLimiter: hunterRatelimiter})
		case "zoomeye":
			agent, err = zoomeye.NewWithOptions(&uncover.AgentOptions{RateLimiter: zoomeyeRatelimiter})
		default:
			err = errors.New("unknown agent type")
		}
		if err != nil {
			return nil, err
		}
		agents = append(agents, agent)
	}
	// enumerate
	var wg sync.WaitGroup
	ret := make(chan string)
	go func() {
		for _, q := range uncoverOptions.Query {
			uncoverQuery := &uncover.Query{
				Query: q,
				Limit: uncoverOptions.Limit,
			}
			for _, agent := range agents {
				wg.Add(1)
				go func(agent uncover.Agent, uncoverQuery *uncover.Query) {
					defer wg.Done()
					keys := uncoverOptions.Provider.GetKeys()
					if keys.Empty() && agent.Name() != "shodan-idb" {
						gologger.Error().Label(agent.Name()).Msgf("empty keys\n")
						return
					}
					session, err := uncover.NewSession(&keys, uncoverOptions.Retries, uncoverOptions.Timeout)
					if err != nil {
						gologger.Error().Label(agent.Name()).Msgf("couldn't create new session: %s\n", err)
					}
					ch, err := agent.Query(session, uncoverQuery)
					if err != nil {
						gologger.Warning().Msgf("%s\n", err)
						return
					}
					for result := range ch {
						ret <- result.IpPort()
					}
				}(agent, uncoverQuery)
			}
		}
		wg.Wait()
		close(ret)
	}()
	return ret, nil
}

func loadProvidersFromEnv(options *ucRunner.Options) error {
	if key, exists := os.LookupEnv("SHODAN_API_KEY"); exists {
		options.Provider.Shodan = append(options.Provider.Shodan, key)
	}
	if id, exists := os.LookupEnv("CENSYS_API_ID"); exists {
		if secret, exists := os.LookupEnv("CENSYS_API_SECRET"); exists {
			options.Provider.Censys = append(options.Provider.Censys, fmt.Sprintf("%s:%s", id, secret))
		} else {
			return errors.New("missing censys secret")
		}
	}
	if email, exists := os.LookupEnv("FOFA_EMAIL"); exists {
		if key, exists := os.LookupEnv("FOFA_KEY"); exists {
			options.Provider.Fofa = append(options.Provider.Fofa, fmt.Sprintf("%s:%s", email, key))
		} else {
			return errors.New("missing fofa key")
		}
	}
	if key, exists := os.LookupEnv("HUNTER_API_KEY"); exists {
		options.Provider.Hunter = append(options.Provider.Hunter, key)
	}
	if key, exists := os.LookupEnv("QUAKE_TOKEN"); exists {
		options.Provider.Quake = append(options.Provider.Quake, key)
	}
	if key, exists := os.LookupEnv("ZOOMEYE_API_KEY"); exists {
		options.Provider.ZoomEye = append(options.Provider.ZoomEye, key)
	}
	return nil
}
