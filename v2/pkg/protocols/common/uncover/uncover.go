package uncover

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
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
	"github.com/remeh/sizedwaitgroup"
)

const maxConcurrentAgents = 50

func GetTargetsFromUncover(delay, limit int, field string, engine, query []string) (chan string, error) {

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
	var rateLimiter *ratelimit.Limiter
	// create rateLimiter for uncover delay
	if uncoverOptions.Delay > 0 {
		rateLimiter = ratelimit.New(context.Background(), 1, time.Duration(uncoverOptions.Delay))
	} else {
		rateLimiter = ratelimit.NewUnlimited(context.Background())
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
			agent, err = shodan.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "censys":
			agent, err = censys.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "fofa":
			agent, err = fofa.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "shodan-idb":
			agent, err = shodanidb.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "quake":
			agent, err = quake.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "hunter":
			agent, err = hunter.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "zoomeye":
			agent, err = zoomeye.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		default:
			err = errors.New("unknown agent type")
		}
		if err != nil {
			return nil, err
		}
		agents = append(agents, agent)
	}
	// enumerate
	swg := sizedwaitgroup.New(maxConcurrentAgents)

	ret := make(chan string)
	go func() {
		for _, q := range uncoverOptions.Query {
			uncoverQuery := &uncover.Query{
				Query: q,
				Limit: uncoverOptions.Limit,
			}
			for _, agent := range agents {
				swg.Add()
				go func(agent uncover.Agent, uncoverQuery *uncover.Query) {
					defer swg.Done()
					keys := uncoverOptions.Provider.GetKeys()
					if !checkKeyExits(agent, keys) {
						gologger.Error().Label(agent.Name()).Msgf("no keys provided")
						return
					}
					session, err := uncover.NewSession(&keys, uncoverOptions.Retries, uncoverOptions.Timeout)
					if err != nil {
						gologger.Error().Label(agent.Name()).Msgf("couldn't create uncover new session: %s", err)
					}
					ch, err := agent.Query(session, uncoverQuery)
					if err != nil {
						gologger.Warning().Msgf("%s", err)
						return
					}
					for result := range ch {
						replacer := strings.NewReplacer(
							"ip", result.IP,
							"host", result.Host,
							"port", fmt.Sprint(result.Port),
						)
						ret <- replacer.Replace(field)
					}
				}(agent, uncoverQuery)
			}
		}
		swg.Wait()
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

func GetUncoverTargetsFromMetadata(templates []*templates.Template, delay, limit int, field string) chan string {
	ret := make(chan string)
	go func() {
		var wg sync.WaitGroup
		for _, template := range templates {
			for k, v := range template.Info.Metadata {
				var engine []string
				var query []string
				switch k {
				case "shodan-query":
					engine = append(engine, "shodan")
				case "fofa-query":
					engine = append(engine, "fofa")
				case "censys-query":
					engine = append(engine, "censys")
				case "quake-query":
					engine = append(engine, "quake")
				case "hunter-query":
					engine = append(engine, "hunter")
				case "zoomeye-query":
					engine = append(engine, "zoomeye")
				default:
					continue
				}
				query = append(query, fmt.Sprintf("%v", v))
				wg.Add(1)
				go func(engine, query []string) {
					ch, _ := GetTargetsFromUncover(delay, limit, field, engine, query)
					for c := range ch {
						ret <- c
					}
					wg.Done()
				}(engine, query)
			}
		}
		wg.Wait()
		close(ret)
	}()
	return ret
}

func checkKeyExits(agent uncover.Agent, keys uncover.Keys) bool {
	switch agent.Name() {
	case "fofa":
		if len(keys.FofaKey) == 0 {
			return false
		}
	case "shodan":
		if len(keys.Shodan) == 0 {
			return false
		}
	case "censys":
		if len(keys.CensysToken) == 0 {
			return false
		}
	case "hunter":
		if len(keys.HunterToken) == 0 {
			return false
		}
	case "zoomeye":
		if len(keys.ZoomEyeToken) == 0 {
			return false
		}
	case "quake":
		if len(keys.QuakeToken) == 0 {
			return false
		}
	}
	return true
}
