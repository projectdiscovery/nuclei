package orca

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/projectdiscovery/utils/errkit"
)

// Flow names a connect-flow delivery mechanism.
type Flow string

const (
	// FlowLoopback is Flow A: the code is delivered to a listener on
	// 127.0.0.1 and the user only has to approve.
	FlowLoopback Flow = "loopback"
	// FlowOutOfBand is Flow B: the consent screen displays a code and the user
	// pastes it back.
	FlowOutOfBand Flow = "oob"

	// defaultAuthTimeout bounds how long a login may wait for the user. The
	// authorization code itself lives 10 minutes, so waiting longer than that
	// only produces a code that can no longer be redeemed.
	defaultAuthTimeout = 10 * time.Minute

	// callbackPath is the loopback listener's path.
	callbackPath = "/cb"

	// maxCallbackRequest bounds what an unauthenticated local client can make
	// us read before the state check runs.
	maxCallbackRequest = 8 << 10
)

// LoginOptions configures one connect attempt.
type LoginOptions struct {
	// Endpoints are the resolved origins.
	Endpoints Endpoints
	// AppName labels the client on the consent screen.
	AppName string
	// Scope defaults to ScopeAPI.
	Scope string
	// Flow selects the delivery mechanism. Empty means FlowLoopback, falling
	// back to FlowOutOfBand when a loopback listener cannot be bound.
	Flow Flow
	// HTTPClient is used for the exchange. Nil uses a bounded default.
	HTTPClient *http.Client
	// Timeout bounds the whole attempt. Zero uses defaultAuthTimeout.
	Timeout time.Duration
	// PromptCode is how the out-of-band flow asks the user for the code. Nil
	// returns a PKCEError of kind rejected, which is what a non-interactive
	// caller should get.
	PromptCode func(authorizeURL string) (string, error)
	// OpenBrowser receives the consent URL. Nil means the URL is only reported
	// through OnAuthorizeURL, so a caller without a browser can still print it.
	OpenBrowser func(authorizeURL string) error
	// OnAuthorizeURL is called with the consent URL as soon as it is known, so
	// the caller can print it for a browser that does not open automatically.
	OnAuthorizeURL func(authorizeURL string)

	// listen binds the loopback callback listener. It is a seam so the
	// fallback to the out-of-band flow can be exercised on a host that cannot
	// accept a callback. Nil uses net.Listen on 127.0.0.1.
	listen func(network, address string) (net.Listener, error)
}

// listen binds the callback listener.
func (o LoginOptions) listenOn(network, address string) (net.Listener, error) {
	if o.listen != nil {
		return o.listen(network, address)
	}

	return net.Listen(network, address)
}

// scope returns the requested scope, defaulting to the inference scope.
func (o LoginOptions) scope() string {
	if strings.TrimSpace(o.Scope) == "" {
		return ScopeAPI
	}

	return o.Scope
}

// client returns a bounded HTTP client for the exchange.
func (o LoginOptions) client() *http.Client {
	if o.HTTPClient != nil {
		return o.HTTPClient
	}

	return &http.Client{Timeout: 30 * time.Second}
}

func (o LoginOptions) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}

	return defaultAuthTimeout
}

// Login runs one connect attempt and returns the issued credential.
//
// On success the credential is persisted before it is returned, so a crash
// between the two cannot lose a key that counts against the per-user issuance
// cap. On failure nothing is stored and any previously stored credential is left
// untouched.
func Login(ctx context.Context, store *CredentialStore, options LoginOptions) (Credential, error) {
	if err := ValidateEndpoints(options.Endpoints); err != nil {
		return Credential{}, err
	}

	pkce, err := NewPKCE()
	if err != nil {
		return Credential{}, err
	}

	result, err := authorizeAndExchange(ctx, options, pkce)
	if err != nil {
		return Credential{}, err
	}

	credential := Credential{
		Key:    result.Key,
		Scope:  result.Scope,
		UserID: result.UserID,
	}
	if store != nil {
		stored, err := store.Save(credential, SourcePKCE)
		if err != nil {
			return Credential{}, err
		}

		return stored, nil
	}

	return credential, nil
}

// authorizeAndExchange obtains a code by the selected flow and redeems it.
func authorizeAndExchange(ctx context.Context, options LoginOptions, pkce PKCE) (ExchangeResult, error) {
	flow := options.Flow
	if flow == "" {
		flow = FlowLoopback
	}

	if flow == FlowOutOfBand {
		code, err := outOfBandCode(ctx, options, pkce)
		if err != nil {
			return ExchangeResult{}, err
		}

		return Exchange(ctx, options.client(), options.Endpoints.Auth, code, pkce.Verifier)
	}

	code, err := loopbackCode(ctx, options, pkce)
	if err != nil {
		var listenerErr *PKCEError
		if errors.As(err, &listenerErr) && listenerErr.Kind == PKCEErrorListener {
			// Nothing has been authorized yet, so falling back is safe and
			// gives a usable login on a host that cannot accept a callback.
			fallback := options
			fallback.Flow = FlowOutOfBand
			fallbackCode, fallbackErr := outOfBandCode(ctx, fallback, pkce)
			if fallbackErr != nil {
				return ExchangeResult{}, fallbackErr
			}

			return Exchange(ctx, options.client(), options.Endpoints.Auth, fallbackCode, pkce.Verifier)
		}

		return ExchangeResult{}, err
	}

	return Exchange(ctx, options.client(), options.Endpoints.Auth, code, pkce.Verifier)
}

// loopbackCode runs Flow A: listen on 127.0.0.1, open the browser, and wait for
// the redirect.
func loopbackCode(ctx context.Context, options LoginOptions, pkce PKCE) (string, error) {
	listener, err := options.listenOn("tcp", "127.0.0.1:0")
	if err != nil {
		return "", &PKCEError{
			Kind:    PKCEErrorListener,
			Message: "could not listen on 127.0.0.1 for the orcarouter redirect",
			Err:     err,
		}
	}

	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()

		return "", NewPKCEError(PKCEErrorListener, "the loopback listener reported an unexpected address")
	}

	callback := fmt.Sprintf("http://127.0.0.1:%d%s", address.Port, callbackPath)
	authorizeURL := AuthorizeURL(options.Endpoints.Auth, callback, pkce, options.AppName, options.scope())

	codes := make(chan string, 1)
	failures := make(chan error, 1)

	server := &http.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			handleCallback(writer, request, pkce, codes, failures)
		}),
		// A local, unauthenticated client must not be able to hold the
		// listener open with a slow request body.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
		close(serveErr)
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	announceAuthorizeURL(options, authorizeURL)

	timer := time.NewTimer(options.timeout())
	defer timer.Stop()

	select {
	case code := <-codes:
		return code, nil
	case err := <-failures:
		return "", err
	case err := <-serveErr:
		if err != nil {
			return "", &PKCEError{Kind: PKCEErrorListener, Message: "the loopback callback listener failed", Err: err}
		}

		return "", NewPKCEError(PKCEErrorListener, "the loopback callback listener stopped before the redirect arrived")
	case <-ctx.Done():
		return "", &PKCEError{Kind: PKCEErrorCanceled, Message: "orcarouter login canceled", Err: ctx.Err()}
	case <-timer.C:
		return "", NewPKCEError(
			PKCEErrorTimeout,
			"timed out waiting for the orcarouter authorization redirect",
		)
	}
}

// handleCallback validates one redirect.
//
// The state is compared before anything else is done with the request, and a
// mismatched state is never turned into a code: the listener is reachable by any
// local process, so an unauthenticated request must not be able to deposit one.
func handleCallback(
	writer http.ResponseWriter,
	request *http.Request,
	pkce PKCE,
	codes chan<- string,
	failures chan<- error,
) {
	if request.URL.Path != callbackPath {
		http.NotFound(writer, request)

		return
	}

	query := request.URL.Query()
	if !pkce.MatchesState(query.Get("state")) {
		// Read and discard a bounded amount so the client sees the response
		// rather than a reset.
		_, _ = io.Copy(io.Discard, io.LimitReader(request.Body, maxCallbackRequest))
		writeCallbackPage(writer, "This authorization response did not belong to the running login. You can close this tab.")
		sendError(failures, NewPKCEError(
			PKCEErrorStateMismatch,
			"the orcarouter redirect carried a state this login did not issue",
		))

		return
	}

	if denied := query.Get("error"); denied != "" {
		writeCallbackPage(writer, "Authorization was declined. You can close this tab.")
		sendError(failures, &PKCEError{
			Kind:    PKCEErrorDenied,
			Message: "orcarouter authorization was declined (" + truncate(denied, 100) + ")",
		})

		return
	}

	code := strings.TrimSpace(query.Get("code"))
	if code == "" {
		writeCallbackPage(writer, "No authorization code was returned. You can close this tab.")
		sendError(failures, NewPKCEError(PKCEErrorRejected, "the orcarouter redirect carried no authorization code"))

		return
	}

	// Tell the browser it is done before the exchange runs, so the user is not
	// left staring at a blank tab while the program continues.
	writeCallbackPage(writer, "Connected. You can close this tab.")
	send(codes, code)
}

func send[T any](channel chan<- T, value T) {
	select {
	case channel <- value:
	default:
	}
}

// sendError queues a callback failure without blocking the HTTP handler.
func sendError(channel chan<- error, err error) {
	select {
	case channel <- err:
	default:
	}
}

// writeCallbackPage serves a short, self-contained page. The text is static and
// escaped, so nothing from the query string is reflected.
func writeCallbackPage(writer http.ResponseWriter, message string) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(writer, "<!doctype html><html><head><meta charset=\"utf-8\"><title>OrcaRouter</title></head>"+
		"<body style=\"font-family:system-ui,sans-serif;margin:3rem\"><p>"+html.EscapeString(message)+"</p></body></html>")
}

// outOfBandCode runs Flow B: the consent screen shows a code and the user pastes
// it back.
func outOfBandCode(ctx context.Context, options LoginOptions, pkce PKCE) (string, error) {
	authorizeURL := AuthorizeURL(
		options.Endpoints.Auth,
		CallbackURLOutOfBand,
		pkce,
		options.AppName,
		options.scope(),
	)
	announceAuthorizeURL(options, authorizeURL)

	if options.PromptCode == nil {
		return "", NewPKCEError(
			PKCEErrorRejected,
			"the out-of-band flow needs a code from the user, but no prompt is available; "+
				"open the authorization url and exchange the code with the verifier this process holds",
		)
	}

	type promptResult struct {
		code string
		err  error
	}
	done := make(chan promptResult, 1)
	go func() {
		code, err := options.PromptCode(authorizeURL)
		done <- promptResult{code: code, err: err}
	}()

	select {
	case result := <-done:
		if result.err != nil {
			return "", &PKCEError{Kind: PKCEErrorCanceled, Message: "reading the authorization code failed", Err: result.err}
		}
		if strings.TrimSpace(result.code) == "" {
			return "", NewPKCEError(PKCEErrorRejected, "no authorization code was entered")
		}

		return result.code, nil
	case <-ctx.Done():
		return "", &PKCEError{Kind: PKCEErrorCanceled, Message: "orcarouter login canceled", Err: ctx.Err()}
	}
}

// announceAuthorizeURL reports the consent URL and opens a browser when one is
// available. The URL carries only the challenge, never the verifier.
func announceAuthorizeURL(options LoginOptions, authorizeURL string) {
	if options.OnAuthorizeURL != nil {
		options.OnAuthorizeURL(authorizeURL)
	}
	if options.OpenBrowser != nil {
		_ = options.OpenBrowser(authorizeURL)
	}
}

// DefaultCredentialSource picks the credential to scan with.
//
// An explicit key always wins, because a user who passed one is stating which
// account to use. Otherwise the stored credential is used, which is what makes a
// login survive a restart instead of minting a new key on every launch.
func DefaultCredentialSource(explicitKey string, store *CredentialStore) CredentialSource {
	if strings.TrimSpace(explicitKey) != "" {
		return APIKeySource{Key: explicitKey}
	}

	return StoredCredentialSource{Store: store}
}

// Redact removes every occurrence of a secret from a string. It is used on any
// value that might reach a log.
func Redact(value string, secrets ...string) string {
	for _, secret := range secrets {
		if strings.TrimSpace(secret) == "" {
			continue
		}
		value = strings.ReplaceAll(value, secret, "[REDACTED]")
	}

	return value
}

// wrapSecretError guarantees a returned error cannot carry a secret, in case a
// transport error embeds the request it failed on.
func wrapSecretError(err error, message string, secrets ...string) error {
	if err == nil {
		return nil
	}

	return errkit.New(Redact(message+": "+err.Error(), secrets...))
}
