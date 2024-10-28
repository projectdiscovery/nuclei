package http

import (
	"context"
	"crypto/tls"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/types/nucleierr"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/utils/errkit"
	iputil "github.com/projectdiscovery/utils/ip"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var (
	// @Host:target overrides the input target with the annotated one (similar to self-contained requests)
	reHostAnnotation = regexp.MustCompile(`(?m)^@Host:\s*(.+)\s*$`)
	// @tls-sni:target overrides the input target with the annotated one
	// special values:
	// request.host: takes the value from the host header
	// target: overrides with the specific value
	reSniAnnotation = regexp.MustCompile(`(?m)^@tls-sni:\s*(.+)\s*$`)
	// @timeout:duration overrides the input timeout with a custom duration
	reTimeoutAnnotation = regexp.MustCompile(`(?m)^@timeout:\s*(.+)\s*$`)
	// @once sets the request to be executed only once for a specific URL
	reOnceAnnotation = regexp.MustCompile(`(?m)^@once\s*$`)

	// ErrTimeoutAnnotationDeadline is the error returned when a specific amount of time was exceeded for a request
	// which was alloted using @timeout annotation this usually means that vulnerability was not found
	// in rare case it could also happen due to network congestion
	// the assigned class is TemplateLogic since this in almost every case means that server is not vulnerable
	ErrTimeoutAnnotationDeadline = errkit.New("timeout annotation deadline exceeded").SetKind(nucleierr.ErrTemplateLogic).Build()
	// ErrRequestTimeoutDeadline is the error returned when a specific amount of time was exceeded for a request
	// this happens when the request execution exceeds alloted time
	ErrRequestTimeoutDeadline = errkit.New("request timeout deadline exceeded when notimeout is set").SetKind(errkit.ErrKindDeadline).Build()
)

type flowMark int

const (
	Once flowMark = iota
)

// parseFlowAnnotations and override requests flow
func parseFlowAnnotations(rawRequest string) (flowMark, bool) {
	var fm flowMark
	// parse request for known override annotations
	var hasFlowOverride bool
	// @once
	if reOnceAnnotation.MatchString(rawRequest) {
		fm = Once
		hasFlowOverride = true
	}

	return fm, hasFlowOverride
}

type annotationOverrides struct {
	request        *retryablehttp.Request
	cancelFunc     context.CancelFunc
	interactshURLs []string
}

// parseAnnotations and override requests settings
func (r *Request) parseAnnotations(rawRequest string, request *retryablehttp.Request) (overrides annotationOverrides, modified bool) {
	// parse request for known override annotations

	// @Host:target
	if hosts := reHostAnnotation.FindStringSubmatch(rawRequest); len(hosts) > 0 {
		value := strings.TrimSpace(hosts[1])
		// handle scheme
		switch {
		case stringsutil.HasPrefixI(value, "http://"):
			request.URL.Scheme = "http"
		case stringsutil.HasPrefixI(value, "https://"):
			request.URL.Scheme = "https"
		}

		value = stringsutil.TrimPrefixAny(value, "http://", "https://")

		if isHostPort(value) {
			request.URL.Host = value
		} else {
			hostPort := value
			port := request.URL.Port()
			if port != "" {
				hostPort = net.JoinHostPort(hostPort, port)
			}
			request.URL.Host = hostPort
		}
		modified = true
	}

	// @tls-sni:target
	if hosts := reSniAnnotation.FindStringSubmatch(rawRequest); len(hosts) > 0 {
		value := strings.TrimSpace(hosts[1])
		value = stringsutil.TrimPrefixAny(value, "http://", "https://")

		var literal bool
		switch value {
		case "request.host":
			value = request.Host
		case "interactsh-url":
			if interactshURL, err := r.options.Interactsh.NewURLWithData("interactsh-url"); err == nil {
				value = interactshURL
			}
			overrides.interactshURLs = append(overrides.interactshURLs, value)
		default:
			literal = true
		}
		ctx := context.WithValue(request.Context(), fastdialer.SniName, value)
		request = request.Clone(ctx)

		if literal {
			request.TLS = &tls.ConnectionState{ServerName: value}
		}
		modified = true
	}

	// @timeout:duration
	if r.connConfiguration.NoTimeout {
		modified = true
		var ctx context.Context

		if duration := reTimeoutAnnotation.FindStringSubmatch(rawRequest); len(duration) > 0 {
			value := strings.TrimSpace(duration[1])
			if parsed, err := time.ParseDuration(value); err == nil {
				// to avoid dos via timeout request annotation in http template we set it to maximum of 2 minutes
				if parsed > 2*time.Minute {
					parsed = 2 * time.Minute
				}
				//nolint:govet // cancelled automatically by withTimeout
				// global timeout is overridden by annotation by replacing context
				ctx, overrides.cancelFunc = context.WithTimeoutCause(context.TODO(), parsed, ErrTimeoutAnnotationDeadline)
				// add timeout value to context
				ctx = context.WithValue(ctx, httpclientpool.WithCustomTimeout{}, httpclientpool.WithCustomTimeout{Timeout: parsed})
				request = request.Clone(ctx)
			}
		} else {
			//nolint:govet // cancelled automatically by withTimeout
			// global timeout is overridden by annotation by replacing context
			ctx, overrides.cancelFunc = context.WithTimeoutCause(context.TODO(), r.options.Options.GetTimeouts().HttpTimeout, ErrRequestTimeoutDeadline)
			request = request.Clone(ctx)
		}
	}

	overrides.request = request

	return
}

func isHostPort(value string) bool {
	_, port, err := net.SplitHostPort(value)
	if err != nil {
		return false
	}
	if !iputil.IsPort(port) {
		return false
	}
	return true
}
