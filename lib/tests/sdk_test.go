package sdk_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/utils/env"
	"github.com/stretchr/testify/require"
	"github.com/tarunKoyalwar/goleak"
)

var knownLeaks = []goleak.Option{
	goleak.Pretty(),
	// net/http transport maintains idle keep-alive connections whose goroutines
	// exit on idle timeout or explicit close - not real leaks.
	goleak.IgnoreAnyFunction("net/http.(*http2ClientConn).readLoop"),
	// expirable LRU cache creates a background goroutine for TTL expiration that persists
	// see: https://github.com/hashicorp/golang-lru/blob/770151e9c8cdfae1797826b7b74c33d6f103fbd8/expirable/expirable_lru.go#L79
	goleak.IgnoreAnyContainingPkg("github.com/hashicorp/golang-lru/v2/expirable"),
	goleak.IgnoreAnyFunction("net/http.(*persistConn).readLoop"),
	goleak.IgnoreAnyFunction("net/http.(*persistConn).writeLoop"),
}

func TestSimpleNuclei(t *testing.T) {
	fn := func() {
		resolver, stopResolver := startSDKTestDNSResolver(t)
		templatePath := writeSDKTestDNSTemplate(t, resolver)

		defer func() {
			stopResolver()
			// resources like leveldb have a delay to commit in-memory resources
			// to disk, typically 1-2 seconds, so we wait for 2 seconds
			time.Sleep(2 * time.Second)
			goleak.VerifyNone(t, knownLeaks...)
		}()
		ne, err := nuclei.NewNucleiEngineCtx(
			context.TODO(),
			nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{templatePath}}),
			nuclei.EnableStatsWithOpts(nuclei.StatsOptions{JSON: true}),
			nuclei.DisableUpdateCheck(),
		)
		require.Nil(t, err)
		ne.LoadTargets([]string{"sdk.test"}, false)
		require.NoError(t, ne.LoadAllTemplates())

		var (
			resultsMu sync.Mutex
			results   []*output.ResultEvent
		)
		err = ne.ExecuteWithCallback(func(event *output.ResultEvent) {
			resultsMu.Lock()
			defer resultsMu.Unlock()
			results = append(results, event)
		})
		require.Nil(t, err)
		require.Len(t, results, 1)
		require.Equal(t, "sdk-simple-dns", results[0].TemplateID)
		defer ne.Close()
	}

	// this is shared test so needs to be run as separate process
	if env.GetEnvOrDefault("TestSimpleNuclei", false) {
		// run as new process
		cmd := exec.Command(os.Args[0], "-test.run=TestSimpleNuclei")
		cmd.Env = append(os.Environ(), "TestSimpleNuclei=true")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("process ran with error %s, output: %s", err, out)
		}
	} else {
		fn()
	}
}

func writeSDKTestDNSTemplate(t *testing.T, resolver string) string {
	t.Helper()

	templatePath := filepath.Join(t.TempDir(), "simple-dns.yaml")
	require.NoError(t, os.WriteFile(templatePath, []byte(fmt.Sprintf(`id: sdk-simple-dns

info:
  name: SDK simple DNS test
  author: pdteam
  severity: info

dns:
  - name: "{{FQDN}}"
    type: A
    resolvers:
      - "%s"
    matchers:
      - type: word
        part: answer
        words:
          - "127.0.0.1"
`, resolver)), 0o600))

	return templatePath
}

func startSDKTestDNSResolver(t *testing.T) (string, func()) {
	t.Helper()

	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)

	started := make(chan struct{})
	serverErr := make(chan error, 1)
	server := &dns.Server{
		PacketConn: listener,
		NotifyStartedFunc: func() {
			close(started)
		},
		Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
			response := new(dns.Msg)
			response.SetReply(request)
			for _, question := range request.Question {
				if question.Qtype == dns.TypeA {
					response.Answer = append(response.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.ParseIP("127.0.0.1"),
					})
				}
			}
			if err := writer.WriteMsg(response); err != nil {
				t.Errorf("could not write DNS response: %v", err)
			}
		}),
	}
	go func() {
		serverErr <- server.ActivateAndServe()
	}()

	select {
	case <-started:
	case err := <-serverErr:
		require.NoError(t, err)
	}

	return listener.LocalAddr().String(), func() {
		require.NoError(t, server.Shutdown())
		require.NoError(t, <-serverErr)
	}
}

func TestSimpleNucleiRemote(t *testing.T) {
	fn := func() {
		defer func() {
			// resources like leveldb have a delay to commit in-memory resources
			// to disk, typically 1-2 seconds, so we wait for 2 seconds
			time.Sleep(2 * time.Second)
			goleak.VerifyNone(t, knownLeaks...)
		}()
		ne, err := nuclei.NewNucleiEngineCtx(
			context.TODO(),
			nuclei.WithTemplatesOrWorkflows(
				nuclei.TemplateSources{
					RemoteTemplates: []string{"https://cloud.projectdiscovery.io/public/nameserver-fingerprint.yaml"},
				},
			),
		)
		require.Nil(t, err)
		ne.LoadTargets([]string{"scanme.sh"}, false) // probe non http/https target is set to false here
		err = ne.LoadAllTemplates()
		require.Nil(t, err, "could not load templates")
		// when callback is nil it nuclei will print JSON output to stdout
		err = ne.ExecuteWithCallback(nil)
		require.Nil(t, err)
		defer ne.Close()
	}
	// this is shared test so needs to be run as separate process
	if env.GetEnvOrDefault("TestSimpleNucleiRemote", false) {
		cmd := exec.Command(os.Args[0], "-test.run=TestSimpleNucleiRemote")
		cmd.Env = append(os.Environ(), "TestSimpleNucleiRemote=true")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("process ran with error %s, output: %s", err, out)
		}
	} else {
		fn()
	}
}

func TestThreadSafeNuclei(t *testing.T) {
	fn := func() {
		resolver, stopResolver := startSDKTestDNSResolver(t)
		templatePath := writeSDKTestDNSTemplate(t, resolver)
		defer func() {
			stopResolver()
			// resources like leveldb have a delay to commit in-memory resources
			// to disk, typically 1-2 seconds, so we wait for 2 seconds
			time.Sleep(2 * time.Second)
			goleak.VerifyNone(t, knownLeaks...)
		}()
		// create nuclei engine with options
		ne, err := nuclei.NewThreadSafeNucleiEngineCtx(context.TODO())
		require.Nil(t, err)

		t.Run("sdk.test", func(t *testing.T) {
			err = ne.ExecuteNucleiWithOpts([]string{"sdk.test"}, nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{templatePath}}), nuclei.DisableUpdateCheck())
			require.Nil(t, err)
		})

		t.Run("sdk-two.test", func(t *testing.T) {
			err = ne.ExecuteNucleiWithOpts([]string{"sdk-two.test"}, nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{templatePath}}), nuclei.DisableUpdateCheck())
			require.Nil(t, err)
		})

		// wait for all scans to finish
		defer ne.Close()
	}

	if env.GetEnvOrDefault("TestThreadSafeNuclei", false) {
		cmd := exec.Command(os.Args[0], "-test.run=TestThreadSafeNuclei")
		cmd.Env = append(os.Environ(), "TestThreadSafeNuclei=true")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("process ran with error %s, output: %s", err, out)
		}
	} else {
		fn()
	}
}

func TestWithVarsNuclei(t *testing.T) {
	fn := func() {
		defer func() {
			// resources like leveldb have a delay to commit in-memory resources
			// to disk, typically 1-2 seconds, so we wait for 2 seconds
			time.Sleep(2 * time.Second)
			goleak.VerifyNone(t, knownLeaks...)
		}()
		ne, err := nuclei.NewNucleiEngineCtx(
			context.TODO(),
			nuclei.EnableSelfContainedTemplates(),
			nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{"http/token-spray/api-1forge.yaml"}}),
			nuclei.WithVars([]string{"token=foobar"}),
			nuclei.WithVerbosity(nuclei.VerbosityOptions{Debug: true}),
		)
		require.Nil(t, err)
		ne.LoadTargets([]string{"scanme.sh"}, true) // probe http/https target is set to true here
		err = ne.ExecuteWithCallback(nil)
		require.Nil(t, err)
		defer ne.Close()
	}
	// this is shared test so needs to be run as separate process
	if env.GetEnvOrDefault("TestWithVarsNuclei", false) {
		cmd := exec.Command(os.Args[0], "-test.run=TestWithVarsNuclei")
		cmd.Env = append(os.Environ(), "TestWithVarsNuclei=true")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("process ran with error %s, output: %s", err, out)
		}
	} else {
		fn()
	}
}
