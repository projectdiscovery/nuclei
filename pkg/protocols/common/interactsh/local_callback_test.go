package interactsh

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

func TestLocalCallbackReceivesHTTPInteraction(t *testing.T) {
	client := newLocalCallbackTestClient(t, "", "")

	generatedURL, err := client.NewURLWithData("{{interactsh-url}}")
	require.NoError(t, err)
	require.NotContains(t, generatedURL, "://")

	id := client.interactionIDFromURL(generatedURL)
	require.Len(t, id, 32)

	httpClient := &http.Client{Timeout: 2 * time.Second}
	request, err := http.NewRequest(http.MethodPost, "http://"+generatedURL+"?source=test", strings.NewReader("local-callback-body"))
	require.NoError(t, err)
	request.Header.Set("X-Nuclei-Test", "local-callback")

	response, err := httpClient.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	require.Equal(t, http.StatusOK, response.StatusCode)

	require.Eventually(t, func() bool {
		interactions, err := client.interactions.Get(id)
		if err != nil {
			return false
		}
		for _, interaction := range interactions {
			if interaction.Protocol == "http" &&
				interaction.UniqueID == id &&
				interaction.RemoteAddress != "" &&
				strings.Contains(interaction.RawRequest, "POST /"+id+"?source=test HTTP/1.1") &&
				strings.Contains(interaction.RawRequest, "X-Nuclei-Test: local-callback") &&
				strings.Contains(interaction.RawRequest, "local-callback-body") &&
				strings.Contains(interaction.RawResponse, "HTTP/1.1 200 OK") {
				return true
			}
		}
		return false
	}, time.Second, 10*time.Millisecond)
}

func TestLocalCallbackMakePlaceholdersUsesPathID(t *testing.T) {
	client := newLocalCallbackTestClient(t, "", "")

	generatedURL, err := client.NewURLWithData("{{interactsh-url}}")
	require.NoError(t, err)

	data := map[string]interface{}{}
	client.MakePlaceholders([]string{generatedURL}, data)

	require.Equal(t, generatedURL, data["interactsh-url"])
	require.Equal(t, client.interactionIDFromURL(generatedURL), data["interactsh-id"])
	require.Equal(t, client.localCallback.hostname(), data["interactsh-server"])
}

func TestLocalCallbackInterfaceChoosesPort(t *testing.T) {
	interfaceName := localCallbackTestInterface(t)
	client := newLocalCallbackTestClientWithInterface(t, interfaceName, 0)

	generatedURL, err := client.NewURLWithData("{{interactsh-url}}")
	require.NoError(t, err)

	parsed, err := parseCallbackURL(generatedURL)
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(parsed.Host)
	require.NoError(t, err)
	require.NotEmpty(t, port)
	require.NotEqual(t, "0", port)

	id := client.interactionIDFromURL(generatedURL)
	response, err := http.Get("http://" + generatedURL)
	require.NoError(t, err)
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	require.Equal(t, http.StatusOK, response.StatusCode)

	require.Eventually(t, func() bool {
		interactions, err := client.interactions.Get(id)
		if err != nil {
			return false
		}
		for _, interaction := range interactions {
			if interaction.Protocol == "http" {
				return true
			}
		}
		return false
	}, time.Second, 10*time.Millisecond)
}

func TestLocalCallbackHTTPInteractionSatisfiesDNSMatcher(t *testing.T) {
	client := newLocalCallbackTestClient(t, "", "")

	generatedURL, err := client.NewURLWithData("{{interactsh-url}}")
	require.NoError(t, err)

	operator := &operators.Operators{
		Matchers: []*matchers.Matcher{{
			Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher},
			DSL:  []string{`interactsh_protocol == "dns"`},
		}},
		MatchersCondition: "and",
	}
	require.NoError(t, operator.Compile())

	requestData := &RequestData{
		Event: &output.InternalWrappedEvent{InternalEvent: output.InternalEvent{
			templateIdAttribute: "local-callback-dns-compatible-test",
		}},
		Operators: operator,
		MatchFunc: func(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
			return matcher.Result(matcher.MatchDSL(data)), []string{}
		},
		ExtractFunc: func(map[string]interface{}, *extractors.Extractor) map[string]struct{} {
			return nil
		},
		MakeResultFunc: func(*output.InternalWrappedEvent) []*output.ResultEvent {
			return nil
		},
	}
	client.RequestEvent([]string{generatedURL}, requestData)

	response, err := http.Get("http://" + generatedURL)
	require.NoError(t, err)
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	require.Equal(t, http.StatusOK, response.StatusCode)

	require.Eventually(t, func() bool {
		requestData.Event.RLock()
		defer requestData.Event.RUnlock()
		return requestData.Event.OperatorsResult != nil &&
			requestData.Event.InternalEvent["interactsh_protocol"] == "dns"
	}, time.Second, 10*time.Millisecond)
}

func TestParseCallbackURLSupportsSchemeLessHostPort(t *testing.T) {
	parsed, err := parseCallbackURL("10.10.14.251:8080/callback")
	require.NoError(t, err)
	require.Equal(t, "http", parsed.Scheme)
	require.Equal(t, "10.10.14.251:8080", parsed.Host)
	require.Equal(t, "/callback", parsed.Path)
}

func newLocalCallbackTestClient(t *testing.T, listenAddress, callbackURL string) *Client {
	t.Helper()
	return newLocalCallbackTestClientWithOptions(t, listenAddress, callbackURL, "", 0)
}

func newLocalCallbackTestClientWithInterface(t *testing.T, interfaceName string, port int) *Client {
	t.Helper()
	return newLocalCallbackTestClientWithOptions(t, "", "", interfaceName, port)
}

func newLocalCallbackTestClientWithOptions(t *testing.T, listenAddress, callbackURL, interfaceName string, port int) *Client {
	t.Helper()
	if listenAddress == "" {
		if callbackURL == "" && interfaceName == "" {
			listenAddress = "127.0.0.1:0"
		}
	}
	client, err := New(&Options{
		CacheSize:              10,
		Eviction:               time.Second,
		CooldownPeriod:         0,
		PollDuration:           10 * time.Millisecond,
		LocalCallbackListen:    listenAddress,
		LocalCallbackURL:       callbackURL,
		LocalCallbackInterface: interfaceName,
		LocalCallbackPort:      port,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		client.Close()
	})
	return client
}

func localCallbackTestInterface(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"lo", "lo0"} {
		iface, err := net.InterfaceByName(name)
		if err == nil && interfaceHasIPv4Address(t, iface) {
			return iface.Name
		}
	}
	ifaces, err := net.Interfaces()
	require.NoError(t, err)
	for _, iface := range ifaces {
		if interfaceHasIPv4Address(t, &iface) {
			return iface.Name
		}
	}
	t.Skip("no interface with an IPv4 address available")
	return ""
}

func interfaceHasIPv4Address(t *testing.T, iface *net.Interface) bool {
	t.Helper()
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ip := ipFromInterfaceAddress(addr)
		if ip != nil && ip.To4() != nil && !ip.IsUnspecified() {
			return true
		}
	}
	return false
}
