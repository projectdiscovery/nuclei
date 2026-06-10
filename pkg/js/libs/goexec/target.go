package goexec

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

func normalizeTarget(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", ErrMissingTarget
	}
	if strings.Contains(target, "://") {
		parsed, err := url.Parse(target)
		if err != nil {
			return "", fmt.Errorf("parse target: %w", err)
		}
		target = parsed.Host
	}
	if host, port, err := net.SplitHostPort(target); err == nil {
		if host == "" {
			return "", ErrMissingTarget
		}
		if port == "" {
			return host, nil
		}
		return net.JoinHostPort(host, port), nil
	}
	if strings.HasPrefix(target, "[") && strings.HasSuffix(target, "]") {
		target = strings.TrimPrefix(strings.TrimSuffix(target, "]"), "[")
		if target == "" {
			return "", ErrMissingTarget
		}
	}
	return target, nil
}

func targetHost(target string) string {
	if host, _, err := net.SplitHostPort(target); err == nil {
		return host
	}
	return target
}
