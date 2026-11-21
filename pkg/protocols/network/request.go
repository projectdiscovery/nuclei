package network

import (
	"crypto/tls"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"maps"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/multierr"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache" //nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/render"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/vardump"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/network/networkclientpool"
	protocolutils "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/utils/errkit"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/projectdiscovery/utils/reader"
	syncutil "github.com/projectdiscovery/utils/sync"
)

var _ protocols.Request = &Request{}

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.NetworkProtocol
}

// getOpenPorts returns all open ports from list of ports provided in template
// if only 1 port is provided, no need to check if port is open or not
func (request *Request) getOpenPorts(target *contextargs.Context) ([]string, error) {
	if len(request.ports) == 1 {
		// no need to check if port is open or not
		return request.ports, nil
	}
	errs := []error{}
	// if more than 1 port is provided, check if port is open or not
	openPorts := make([]string, 0)
	for _, port := range request.ports {
		cloned := target.Clone()
		if err := cloned.UseNetworkPort(port, request.ExcludePorts); err != nil {
			errs = append(errs, err)
			continue
		}
		addr, err := getAddress(cloned.MetaInput.Input)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if request.dialer == nil {
			request.dialer, _ = networkclientpool.Get(request.options.Options, &networkclientpool.Configuration{})
		}

		if err := request.options.HostBackoffWait(target.Context(), addr); err != nil {
			return nil, err
		}
		conn, err := request.dialer.Dial(target.Context(), "tcp", addr)
		request.options.HostBackoffObserveDial(addr, err)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		_ = conn.Close()
		openPorts = append(openPorts, port)
	}
	if len(openPorts) == 0 {
		return nil, multierr.Combine(errs...)
	}
	return openPorts, nil
}

// countUnsent counts n requests an execution never started as processed, with
// no error (#7838). Each request counts once, at the deepest level it reaches:
// executeRequestWithPayloads counts each request it is given, and each loop
// counts here the ones it doesn't start.
func (request *Request) countUnsent(n int) {
	if n > 0 {
		request.options.Progress.SetRequests(uint64(n))
	}
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(target *contextargs.Context, metadata, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	visitedAddresses := make(mapsutil.Map[string, struct{}])

	if request.Port == "" {
		// backwords compatibility or for other use cases
		// where port is not provided in template
		if err := request.executeOnTarget(target, visitedAddresses, metadata, previous, callback); err != nil {
			return err
		}
	}

	// The total counts every listed port, so a port the loop doesn't start counts
	// as processed: one the port check finds closed, or one the loop doesn't reach.
	started := 0
	defer func() {
		request.countUnsent((len(request.ports) - started) * len(request.addresses) * request.requestsPerAddress())
	}()

	// get open ports from list of ports provided in template
	ports, err := request.getOpenPorts(target)
	if len(ports) == 0 {
		return err
	}
	if err != nil {
		// TODO: replace this after scan context is implemented
		gologger.Verbose().Msgf("[%v] got errors while checking open ports: %s\n", request.options.TemplateID, err)
	}

	// stop at first match if requested
	atomicBool := &atomic.Bool{}
	shouldStopAtFirstMatch := request.StopAtFirstMatch || request.options.StopAtFirstMatch || request.options.Options.StopAtFirstMatch
	wrappedCallback := func(event *output.InternalWrappedEvent) {
		if event != nil && event.HasOperatorResult() {
			atomicBool.Store(true)
		}
		callback(event)
	}

	var (
		skipped  bool
		failures error
	)

	for _, port := range ports {
		// A cancel ends the scan. It is not a failure of this port, and every port
		// after it would report the same one.
		ctxErr := target.Context().Err()
		if ctxErr != nil {
			return errors.Wrap(ctxErr, "network scan canceled")
		}

		input := target.Clone()
		// use network port updates input with new port requested in template file
		// and it is ignored if input port is not standard http(s) ports like 80,8080,8081 etc
		// idea is to reduce redundant dials to http ports
		if err := input.UseNetworkPort(port, request.ExcludePorts); err != nil {
			gologger.Debug().Msgf("Could not network port from constants: %s\n", err)
		}

		started++
		targetErr := request.executeOnTarget(input, visitedAddresses, metadata, previous, wrappedCallback)
		if stderrors.Is(targetErr, hosterrorscache.ErrUnresponsiveHost) {
			skipped = true
		} else if targetErr != nil {
			// Each port is its own service, so a failure on one doesn't stop the
			// others, as in the javascript protocol. errkit joins them, as
			// getErrorCause reads the cause of an errkit error only.
			if failures == nil {
				failures = targetErr
			} else {
				failures = errkit.Append(failures, targetErr)
			}
		}
		if shouldStopAtFirstMatch && atomicBool.Load() {
			break
		}
	}

	// A failed port takes precedence over a skipped one, as an address does. The
	// skip is never joined into the failures, so errors.Is(err,
	// ErrUnresponsiveHost) still means that no port failed.
	if failures != nil {
		//nolint:wrapcheck // the failures are returned as they came, joined or not, so a caller sees the errors of its ports
		return failures
	}

	if skipped {
		return hosterrorscache.ErrUnresponsiveHost
	}

	return nil
}

func (request *Request) executeOnTarget(input *contextargs.Context, visited mapsutil.Map[string, struct{}], metadata, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	// An address the loop doesn't start counts as processed, whether it breaks,
	// skips a visited address or returns on a cancel or an error.
	started := 0
	defer func() {
		request.countUnsent((len(request.addresses) - started) * request.requestsPerAddress())
	}()

	var address string
	var err error

	if request.SelfContained {
		address = ""
	} else {
		address, err = getAddress(input.MetaInput.Input)
	}

	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, input.MetaInput.Input, request.Type().String(), err)
		// The deferred count counts the requests this input would have sent.
		request.options.Progress.IncrementErrorsBy(1)
		return errors.Wrap(err, "could not get address from url")
	}

	variables := protocolutils.GenerateVariables(address, false, nil)
	scope := request.options.NewVariablesScope(variables)

	request.options.AddTemplateCtxToVariablesScope(input.MetaInput, scope)
	scope.AddData(request.options.Constants)

	evaluation := request.options.Variables.EvaluateWithInteractshScope(scope, request.options.Interactsh)
	variablesMap, interactshURLs := evaluation.Values, evaluation.InteractURLs

	// add template ctx variables to varMap
	if request.options.HasTemplateCtx(input.MetaInput) {
		variables = generators.MergeMaps(variables, request.options.GetTemplateCtx(input.MetaInput).GetAll())
	}

	variables = generators.MergeMaps(variablesMap, variables, request.options.Constants)

	// stop at first match if requested
	atomicBool := &atomic.Bool{}
	shouldStopAtFirstMatch := request.StopAtFirstMatch || request.options.StopAtFirstMatch || request.options.Options.StopAtFirstMatch
	wrappedCallback := func(event *output.InternalWrappedEvent) {
		if event != nil && event.HasOperatorResult() {
			atomicBool.Store(true)
		}
		callback(event)
	}

	var (
		skipped bool
		failErr error
	)

	for _, kv := range request.addresses {
		select {
		case <-input.Context().Done():
			return input.Context().Err()
		default:
		}

		actualAddress := replacer.Replace(kv.address, variables)

		if visited.Has(actualAddress) && !request.options.Options.DisableClustering {
			continue
		}

		visited.Set(actualAddress, struct{}{})

		started++
		addressErr := request.executeAddress(variables, actualAddress, address, input, kv.tls, previous,
			interactshURLs, wrappedCallback)

		switch {
		case stderrors.Is(addressErr, hosterrorscache.ErrUnresponsiveHost):
			// A failed address takes precedence over the skip, which is
			// reported below only when no address failed.
			skipped = true
		case addressErr != nil:
			err = addressErr
			failErr = addressErr
			outputEvent := request.responseToDSLMap("", "", "", address, "")
			gologger.Warning().Msgf("[%v] Could not make network request for (%s) : %s\n", request.options.TemplateID, actualAddress, err)

			callback(&output.InternalWrappedEvent{InternalEvent: outputEvent})
		default:
			err = nil
		}

		if shouldStopAtFirstMatch && atomicBool.Load() {
			break
		}
	}

	if skipped {
		if failErr != nil {
			return failErr
		}

		return hosterrorscache.ErrUnresponsiveHost
	}

	return err
}

// executeAddress executes the request for an address
func (request *Request) executeAddress(variables map[string]interface{}, actualAddress, address string, input *contextargs.Context, shouldUseTLS bool, previous output.InternalEvent, interactshURLs []string, callback protocols.OutputEventCallback) error {
	// A request the loop below doesn't start counts as processed: a payload it
	// skips, one that fails to render, and the rest after a cancel or a skip.
	started := 0
	defer func() {
		request.countUnsent(request.requestsPerAddress() - started)
	}()

	variables = generators.MergeMaps(variables, map[string]interface{}{"Hostname": address})
	payloads := generators.BuildPayloadFromOptions(request.options.Options)

	if !strings.Contains(actualAddress, ":") {
		err := errors.New("no port provided in network protocol request")
		request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
		// The deferred count counts the requests this address would have sent.
		request.options.Progress.IncrementErrorsBy(1)
		return err
	}
	updatedTarget := input.Clone()
	updatedTarget.MetaInput.Input = actualAddress

	// if request threads matches global payload concurrency we follow it
	shouldFollowGlobal := request.Threads == request.options.Options.PayloadConcurrency

	if request.generator != nil {
		iterator := request.generator.NewIterator()
		var multiErr error
		m := &sync.Mutex{}
		skipped := &atomic.Bool{}
		swg, err := syncutil.New(syncutil.WithSize(request.Threads))
		if err != nil {
			return err
		}

	payloadLoop:
		for {
			value, ok := iterator.Value()
			if !ok {
				break
			}

			select {
			case <-input.Context().Done():
				break payloadLoop
			default:
			}

			// resize check point - nop if there are no changes
			if shouldFollowGlobal && swg.Size != request.options.Options.PayloadConcurrency {
				if err := swg.Resize(input.Context(), request.options.Options.PayloadConcurrency); err != nil {
					m.Lock()
					multiErr = multierr.Append(multiErr, err)
					m.Unlock()
				}
			}
			if request.isUnresponsiveAddress(updatedTarget) {
				// The remaining payloads would be skipped as well, and the
				// deferred count counts them. Wait for the running ones, as an
				// error of theirs takes precedence.
				skipped.Store(true)

				break payloadLoop
			}

			renderedValue, err := render.RenderMap(render.MapInput{
				Options:      request.options.GetOptions(),
				Source:       value,
				Data:         payloads,
				Values:       generators.MergeMaps(variables, value, payloads),
				Interactsh:   request.options.Interactsh,
				InteractURLs: interactshURLs,
			})
			if err != nil {
				request.options.Progress.IncrementErrorsBy(1)
				m.Lock()
				multiErr = multierr.Append(multiErr, errors.Wrap(err, "could not evaluate payload helper expressions"))
				m.Unlock()
				continue
			}

			if err := swg.AddWithContext(input.Context()); err != nil {
				break payloadLoop
			}

			started++
			go func(vars map[string]interface{}, urls []string) {
				defer swg.Done()

				err := request.executeRequestWithPayloads(variables, actualAddress, address, input, shouldUseTLS, vars,
					previous, urls, callback)
				if stderrors.Is(err, hosterrorscache.ErrUnresponsiveHost) {
					skipped.Store(true)
				} else if err != nil {
					m.Lock()
					multiErr = multierr.Append(multiErr, err)
					m.Unlock()
				}
			}(renderedValue.Values, renderedValue.InteractURLs)
		}

		swg.Wait()
		if err := input.Context().Err(); err != nil {
			return err
		}

		if multiErr != nil {
			return multiErr
		}

		if skipped.Load() {
			return hosterrorscache.ErrUnresponsiveHost
		}
	} else {
		value := maps.Clone(payloads)
		started++
		if err := request.executeRequestWithPayloads(variables, actualAddress, address, input, shouldUseTLS, value, previous, interactshURLs, callback); err != nil {
			return err
		}
	}

	return nil
}

func (request *Request) executeRequestWithPayloads(variables map[string]interface{}, actualAddress, address string, input *contextargs.Context, shouldUseTLS bool, payloads map[string]interface{}, previous output.InternalEvent, interactshURLs []string, callback protocols.OutputEventCallback) error {
	var (
		hostname string
		conn     net.Conn
		err      error
	)
	if host, _, err := net.SplitHostPort(actualAddress); err == nil {
		hostname = host
	}
	updatedTarget := input.Clone()
	updatedTarget.MetaInput.Input = actualAddress

	if request.isUnresponsiveAddress(updatedTarget) {
		// A skip is a processed request, not an error.
		request.options.Progress.IncrementRequests()

		return hosterrorscache.ErrUnresponsiveHost
	}

	if err := request.options.HostBackoffWait(input.Context(), actualAddress); err != nil {
		request.options.Progress.IncrementFailedRequestsBy(1)
		return err
	}
	if err := request.options.RateLimitTakeContext(input.Context(), actualAddress); err != nil {
		request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not take rate limit")
	}

	if shouldUseTLS {
		conn, err = request.dialer.DialTLS(input.Context(), "tcp", actualAddress)
	} else {
		conn, err = request.dialer.Dial(input.Context(), "tcp", actualAddress)
	}
	// DialTLS fails the handshake after TCP has connected. Backoff follows the
	// TCP result; the request still returns the handshake error.
	request.options.HostBackoffObserveDial(actualAddress, tcpDialError(err))
	// adds it to unresponsive address list if applicable
	request.markHostError(updatedTarget, err)
	if err != nil {
		request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
		request.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not connect to server")
	}
	defer func() {
		_ = conn.Close()
	}()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(request.options.Options.Timeout) * time.Second))

	interactshURLs = append([]string(nil), interactshURLs...)

	var responseBuilder, reqBuilder strings.Builder

	interimValues := generators.MergeMaps(variables, payloads)

	if vardump.EnableVarDump {
		gologger.Debug().Msgf("Network Protocol request variables: %s\n", vardump.DumpVariables(interimValues))
	}

	inputEvents := make(map[string]interface{})
	var stepDurations []time.Duration

	for _, input := range request.Inputs {
		result, err := render.Render(render.Input{
			Options:      request.options.GetOptions(),
			Text:         input.Data,
			Values:       interimValues,
			Interactsh:   request.options.Interactsh,
			InteractURLs: interactshURLs,
		})
		if err != nil {
			request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
			request.options.Progress.IncrementFailedRequestsBy(1)

			return errors.Wrap(err, "could not evaluate template expressions")
		}

		data := result.Text
		dataInBytes := []byte(data)
		interactshURLs = result.InteractURLs

		if err := expressions.ContainsUnresolvedVariables(data); err != nil {
			gologger.Warning().Msgf("[%s] Could not make network request for %s: %v\n", request.options.TemplateID, actualAddress, err)
			// Unresolved variables are a skip, not an error, as in http.
			request.options.Progress.IncrementRequests()

			return nil
		}

		if input.Type.GetType() == hexType {
			dataInBytes, err = hex.DecodeString(data)
			if err != nil {
				request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
				request.options.Progress.IncrementFailedRequestsBy(1)
				return errors.Wrap(err, "could not write request to server")
			}
		}

		reqBuilder.Write(dataInBytes)
		timeStart := time.Now()
		if _, err := conn.Write(dataInBytes); err != nil {
			request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), err)
			request.options.Progress.IncrementFailedRequestsBy(1)
			return errors.Wrap(err, "could not write request to server")
		}

		if input.Read > 0 {
			buffer, err := ConnReadNWithTimeout(conn, int64(input.Read), request.options.Options.GetTimeouts().TcpReadTimeout)
			if err != nil {
				request.options.Progress.IncrementFailedRequestsBy(1)
				return errkit.Wrap(err, "could not read response from connection")
			}
			stepDurations = append(stepDurations, time.Since(timeStart))

			responseBuilder.Write(buffer)

			bufferStr := string(buffer)
			if input.Name != "" {
				inputEvents[input.Name] = bufferStr
				interimValues[input.Name] = bufferStr
			}

			// Run any internal extractors for the request here and add found values to map.
			if request.CompiledOperators != nil {
				values := request.CompiledOperators.ExecuteInternalExtractors(map[string]interface{}{input.Name: bufferStr}, request.Extract)
				maps.Copy(payloads, values)
			}
		} else {
			stepDurations = append(stepDurations, time.Since(timeStart))
		}
	}

	request.options.Progress.IncrementRequests()

	if request.options.Options.Debug || request.options.Options.DebugRequests || request.options.Options.StoreResponse {
		requestBytes := []byte(reqBuilder.String())
		msg := fmt.Sprintf("[%s] Dumped Network request for %s\n%s", request.options.TemplateID, actualAddress, hex.Dump(requestBytes))
		if request.options.Options.Debug || request.options.Options.DebugRequests {
			gologger.Info().Str("address", actualAddress).Msg(msg)
		}
		if request.options.Options.StoreResponse {
			request.options.Output.WriteStoreDebugData(address, request.options.TemplateID, request.Type().String(), msg)
		}
		if request.options.Options.VerboseVerbose {
			gologger.Print().Msgf("\nCompact HEX view:\n%s", hex.EncodeToString(requestBytes))
		}
	}

	request.options.Output.Request(request.options.TemplatePath, actualAddress, request.Type().String(), err)
	gologger.Verbose().Msgf("Sent TCP request to %s", actualAddress)

	bufferSize := 1024
	if request.ReadSize != 0 {
		bufferSize = request.ReadSize
	}
	if request.ReadAll {
		bufferSize = -1
	}

	final, readErr := ConnReadNWithTimeout(conn, int64(bufferSize), request.options.Options.GetTimeouts().TcpReadTimeout)
	if readErr != nil {
		request.options.Output.Request(request.options.TemplatePath, address, request.Type().String(), readErr)
		gologger.Verbose().Msgf("could not read more data from %s: %s", actualAddress, readErr)
	}
	responseBuilder.Write(final)

	response := responseBuilder.String()
	outputEvent := request.responseToDSLMap(reqBuilder.String(), string(final), response, input.MetaInput.Input, actualAddress)
	addDurationFields(outputEvent, stepDurations)
	// add response fields to template context and merge templatectx variables to output event
	request.options.AddTemplateVars(input.MetaInput, request.Type(), request.ID, outputEvent)
	if request.options.HasTemplateCtx(input.MetaInput) {
		outputEvent = generators.MergeMaps(outputEvent, request.options.GetTemplateCtx(input.MetaInput).GetAll())
	}
	if input.MetaInput.CustomIP != "" {
		outputEvent["ip"] = input.MetaInput.CustomIP
	} else {
		outputEvent["ip"] = request.dialer.GetDialedIP(hostname)
	}
	if request.options.StopAtFirstMatch {
		outputEvent["stop-at-first-match"] = true
	}
	maps.Copy(outputEvent, previous)
	maps.Copy(outputEvent, interimValues)
	maps.Copy(outputEvent, inputEvents)
	if request.options.Interactsh != nil {
		request.options.Interactsh.MakePlaceholders(interactshURLs, outputEvent)
	}

	var event *output.InternalWrappedEvent
	if len(interactshURLs) == 0 {
		event = eventcreator.CreateEventWithAdditionalOptions(request, generators.MergeMaps(payloads, outputEvent), request.options.Options.Debug || request.options.Options.DebugResponse, func(wrappedEvent *output.InternalWrappedEvent) {
			wrappedEvent.OperatorsResult.PayloadValues = payloads
		})
		callback(event)
	} else if request.options.Interactsh != nil {
		event = &output.InternalWrappedEvent{InternalEvent: outputEvent}
		request.options.RegisterInteractshRequest(interactshURLs, &interactsh.RequestData{
			MakeResultFunc: request.MakeResultEvent,
			Event:          event,
			Operators:      request.CompiledOperators,
			MatchFunc:      request.Match,
			ExtractFunc:    request.Extract,
		})
	}
	if len(interactshURLs) > 0 {
		event.UsesInteractsh = true
	}

	dumpResponse(event, request, response, actualAddress, address)

	return nil
}

func addDurationFields(event output.InternalEvent, durations []time.Duration) {
	for i, duration := range durations {
		seconds := duration.Seconds()
		event[fmt.Sprintf("duration_%d", i+1)] = seconds
		event["duration"] = seconds
	}
}

func dumpResponse(event *output.InternalWrappedEvent, request *Request, response string, actualAddress, address string) {
	cliOptions := request.options.Options
	if cliOptions.Debug || cliOptions.DebugResponse || cliOptions.StoreResponse {
		requestBytes := []byte(response)
		highlightedResponse := responsehighlighter.Highlight(event.OperatorsResult, hex.Dump(requestBytes), cliOptions.NoColor, true)
		msg := fmt.Sprintf("[%s] Dumped Network response for %s\n\n", request.options.TemplateID, actualAddress)
		if cliOptions.Debug || cliOptions.DebugResponse {
			gologger.Debug().Msg(fmt.Sprintf("%s%s", msg, highlightedResponse))
		}
		if cliOptions.StoreResponse {
			request.options.Output.WriteStoreDebugData(address, request.options.TemplateID, request.Type().String(), fmt.Sprintf("%s%s", msg, hex.Dump(requestBytes)))
		}
		if cliOptions.VerboseVerbose {
			displayCompactHexView(event, response, cliOptions.NoColor)
		}
	}
}

func displayCompactHexView(event *output.InternalWrappedEvent, response string, noColor bool) {
	operatorsResult := event.OperatorsResult
	if operatorsResult != nil {
		var allMatches []string
		for _, namedMatch := range operatorsResult.Matches {
			for _, matchElement := range namedMatch {
				allMatches = append(allMatches, hex.EncodeToString([]byte(matchElement)))
			}
		}
		tempOperatorResult := &operators.Result{Matches: map[string][]string{"matchesInHex": allMatches}}
		gologger.Print().Msgf("\nCompact HEX view:\n%s", responsehighlighter.Highlight(tempOperatorResult, hex.EncodeToString([]byte(response)), noColor, false))
	}
}

// tcpDialError reports a failure to open TCP. A TLS handshake error means the
// port already accepted the connection.
func tcpDialError(err error) error {
	if err == nil {
		return nil
	}
	var record tls.RecordHeaderError
	if stderrors.As(err, &record) {
		return nil
	}
	message := err.Error()
	if strings.Contains(message, "tls:") || strings.Contains(message, "tls handshake") {
		return nil
	}
	return err
}

// getAddress returns the address of the host to make request to
func getAddress(toTest string) (string, error) {
	if strings.Contains(toTest, "://") {
		parsed, err := url.Parse(toTest)
		if err != nil {
			return "", err
		}
		toTest = parsed.Host
	}
	return toTest, nil
}

func ConnReadNWithTimeout(conn net.Conn, n int64, timeout time.Duration) ([]byte, error) {
	switch n {
	case -1:
		// if n is -1 then read all available data from connection
		return reader.ConnReadNWithTimeout(conn, -1, timeout)
	case 0:
		n = 4096 // default buffer size
	}
	b := make([]byte, n)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	count, err := conn.Read(b)
	_ = conn.SetDeadline(time.Time{})
	if err != nil && os.IsTimeout(err) && count > 0 {
		// in case of timeout with some value read, return the value
		return b[:count], nil
	}
	if err != nil {
		return nil, err
	}
	return b[:count], nil
}

// markHostError checks if the error is a unreponsive host error and marks it
func (request *Request) markHostError(input *contextargs.Context, err error) {
	if request.options.HostErrorsCache != nil {
		request.options.HostErrorsCache.MarkFailedOrRemove(request.options.ProtocolType.String(), input, err)
	}
}

// isUnresponsiveAddress checks if the error is a unreponsive based on its execution history
func (request *Request) isUnresponsiveAddress(input *contextargs.Context) bool {
	if request.options.HostErrorsCache != nil {
		return request.options.HostErrorsCache.Check(request.options.ProtocolType.String(), input)
	}
	return false
}
