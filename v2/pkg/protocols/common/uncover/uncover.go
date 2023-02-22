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
	"github.com/projectdiscovery/uncover/uncover/agent/criminalip"
	"github.com/projectdiscovery/uncover/uncover/agent/fofa"
	"github.com/projectdiscovery/uncover/uncover/agent/hunter"
	"github.com/projectdiscovery/uncover/uncover/agent/netlas"
	"github.com/projectdiscovery/uncover/uncover/agent/quake"
	"github.com/projectdiscovery/uncover/uncover/agent/shodan"
	"github.com/projectdiscovery/uncover/uncover/agent/shodanidb"
	"github.com/projectdiscovery/uncover/uncover/agent/zoomeye"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/remeh/sizedwaitgroup"
)

const maxConcurrentAgents = 50

func GetUncoverSupportedAgents() string {
	uncoverSupportedAgents := []string{"shodan", "shodan-idb", "fofa", "censys", "quake", "hunter", "zoomeye", "netlas", "criminalip"}
	return strings.Join(uncoverSupportedAgents, ",")
}

func GetTargetsFromUncover(delay, limit int, field string, engine, query []string) (chan string, error) {
	uncoverOptions := &ucRunner.Options{
		Provider: &ucRunner.Provider{},
		Delay:    delay,
		Limit:    limit,
		Query:    query,
		Engine:   engine,
	}
	for _, eng := range engine {
		err := loadKeys(eng, uncoverOptions)
		if err != nil {
			gologger.Error().Label("WRN").Msgf(err.Error())
			continue
		}
	}
	return getTargets(uncoverOptions, field)
}

func GetUncoverTargetsFromMetadata(templates []*templates.Template, delay, limit int, field string) chan string {
	ret := make(chan string)
	var uqMap = make(map[string][]string)
	var eng, query string
	for _, template := range templates {
		for k, v := range template.Info.Metadata {
			switch k {
			case "shodan-query":
				eng = "shodan"
			case "fofa-query":
				eng = "fofa"
			case "censys-query":
				eng = "censys"
			case "quake-query":
				eng = "quake"
			case "hunter-query":
				eng = "hunter"
			case "zoomeye-query":
				eng = "zoomeye"
			case "netlas-query":
				eng = "netlas"
			case "criminalip-query":
				eng = "criminalip"
			default:
				continue
			}
			query = fmt.Sprintf("%v", v)
			uqMap[eng] = append(uqMap[eng], query)
		}
	}
	keys := mapsutil.GetKeys(uqMap)
	gologger.Info().Msgf("Running uncover query against: %s", strings.Join(keys, ","))
	var wg sync.WaitGroup
	go func() {
		for k, v := range uqMap {
			wg.Add(1)
			go func(engine, query []string) {
				ch, _ := GetTargetsFromUncover(delay, limit, field, engine, query)
				for c := range ch {
					ret <- c
				}
				wg.Done()
			}([]string{k}, v)
		}
		wg.Wait()
		close(ret)
	}()
	return ret
}

func getTargets(uncoverOptions *ucRunner.Options, field string) (chan string, error) {
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
		case "netlas":
			agent, err = netlas.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		case "criminalip":
			agent, err = criminalip.NewWithOptions(&uncover.AgentOptions{RateLimiter: rateLimiter})
		default:
			err = errors.Errorf("%s unknown uncover agent type", engine)
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

func loadKeys(engine string, options *ucRunner.Options) error {
	switch engine {
	case "fofa":
		if email, exists := os.LookupEnv("FOFA_EMAIL"); exists {
			if key, exists := os.LookupEnv("FOFA_KEY"); exists {
				options.Provider.Fofa = append(options.Provider.Fofa, fmt.Sprintf("%s:%s", email, key))
			} else {
				return errors.New("missing FOFA_KEY env variable")
			}
		} else {
			return errors.Errorf("FOFA_EMAIL & FOFA_KEY env variables are not configured")
		}
	case "shodan":
		if key, exists := os.LookupEnv("SHODAN_API_KEY"); exists {
			options.Provider.Shodan = append(options.Provider.Shodan, key)
		} else {
			return errors.Errorf("SHODAN_API_KEY env variable is not configured")
		}
	case "censys":
		if id, exists := os.LookupEnv("CENSYS_API_ID"); exists {
			if secret, exists := os.LookupEnv("CENSYS_API_SECRET"); exists {
				options.Provider.Censys = append(options.Provider.Censys, fmt.Sprintf("%s:%s", id, secret))
			} else {
				return errors.New("missing CENSYS_API_SECRET env variable")
			}
		} else {
			return errors.Errorf("CENSYS_API_ID & CENSYS_API_SECRET env variable is not configured")
		}
	case "hunter":
		if key, exists := os.LookupEnv("HUNTER_API_KEY"); exists {
			options.Provider.Hunter = append(options.Provider.Hunter, key)
		} else {
			return errors.Errorf("HUNTER_API_KEY env variable is not configured")
		}
	case "zoomeye":
		if key, exists := os.LookupEnv("ZOOMEYE_API_KEY"); exists {
			options.Provider.ZoomEye = append(options.Provider.ZoomEye, key)
		} else {
			return errors.Errorf("ZOOMEYE_API_KEY env variable is not configured")
		}
	case "quake":
		if key, exists := os.LookupEnv("QUAKE_TOKEN"); exists {
			options.Provider.Quake = append(options.Provider.Quake, key)
		} else {
			return errors.Errorf("QUAKE_TOKEN env variable is not configured")
		}
	case "netlas":
		if key, exists := os.LookupEnv("NETLAS_API_KEY"); exists {
			options.Provider.Netlas = append(options.Provider.Netlas, key)
		} else {
			return errors.Errorf("NETLAS_API_KEY env variable is not configured")
		}
	case "criminalip":
		if key, exists := os.LookupEnv("CRIMINALIP_API_KEY"); exists {
			options.Provider.CriminalIP = append(options.Provider.CriminalIP, key)
		} else {
			return errors.Errorf("CRIMINALIP_API_KEY env variable is not configured")
		}
	default:
		return errors.Errorf("unknown uncover agent")
	}
	return nil
}
