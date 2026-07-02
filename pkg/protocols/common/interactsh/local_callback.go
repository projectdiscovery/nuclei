package interactsh

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/server"
)

const localCallbackMaxBody = 1024 * 1024

type localCallbackOptions struct {
	listenAddress string
	callbackURL   string
	interfaceName string
	port          int
}

type localCallbackServer struct {
	callbackBase  *url.URL
	httpServer    *http.Server
	listener      net.Listener
	onInteraction func(*server.Interaction)
}

func newLocalCallbackServer(options localCallbackOptions, onInteraction func(*server.Interaction)) (*localCallbackServer, error) {
	if options.listenAddress == "" && options.callbackURL == "" && options.interfaceName == "" {
		return nil, fmt.Errorf("local callback listen address, URL, or interface is required")
	}
	if options.listenAddress == "" && options.interfaceName != "" {
		listenAddress, err := listenAddressFromInterface(options.interfaceName, options.port)
		if err != nil {
			return nil, err
		}
		options.listenAddress = listenAddress
	}
	if options.listenAddress == "" {
		parsed, err := parseCallbackURL(options.callbackURL)
		if err != nil {
			return nil, err
		}
		options.listenAddress = parsed.Host
	}

	listener, err := net.Listen("tcp", options.listenAddress)
	if err != nil {
		return nil, err
	}

	callbackBase, err := callbackURLForListener(options.callbackURL, listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		return nil, err
	}

	server := &localCallbackServer{
		callbackBase:  callbackBase,
		listener:      listener,
		onInteraction: onInteraction,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", server.handle)
	server.httpServer = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return server, nil
}

func listenAddressFromInterface(interfaceName string, port int) (string, error) {
	if port < 0 || port > 65535 {
		return "", fmt.Errorf("callback port must be between 0 and 65535")
	}
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return "", fmt.Errorf("could not find callback interface %q: %w", interfaceName, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("could not get addresses for callback interface %q: %w", interfaceName, err)
	}

	var firstIPv6 net.IP
	for _, addr := range addrs {
		ip := ipFromInterfaceAddress(addr)
		if ip == nil || ip.IsUnspecified() {
			continue
		}
		if ipv4 := ip.To4(); ipv4 != nil {
			return net.JoinHostPort(ipv4.String(), strconv.Itoa(port)), nil
		}
		if firstIPv6 == nil {
			firstIPv6 = ip
		}
	}
	if firstIPv6 != nil {
		return net.JoinHostPort(firstIPv6.String(), strconv.Itoa(port)), nil
	}
	return "", fmt.Errorf("could not find a usable IP address for callback interface %q", interfaceName)
}

func ipFromInterfaceAddress(addr net.Addr) net.IP {
	switch typed := addr.(type) {
	case *net.IPNet:
		return typed.IP
	case *net.IPAddr:
		return typed.IP
	default:
		return nil
	}
}

func parseCallbackURL(callbackURL string) (*url.URL, error) {
	if !strings.Contains(callbackURL, "://") {
		callbackURL = "http://" + callbackURL
	}
	parsed, err := url.Parse(callbackURL)
	if err != nil {
		return nil, fmt.Errorf("could not parse callback URL: %w", err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("callback URL must include a host")
	}
	return parsed, nil
}

func callbackURLForListener(callbackURL, listenAddress string) (*url.URL, error) {
	if callbackURL != "" {
		return parseCallbackURL(callbackURL)
	}

	host, port, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return nil, fmt.Errorf("could not parse callback listen address: %w", err)
	}
	if host == "" || host == "::" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	return &url.URL{Scheme: "http", Host: net.JoinHostPort(host, port)}, nil
}

func (s *localCallbackServer) start() {
	_ = s.httpServer.Serve(s.listener)
}

func (s *localCallbackServer) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.httpServer.Shutdown(ctx)
}

func (s *localCallbackServer) hostname() string {
	return s.callbackBase.Host
}

func (s *localCallbackServer) newURL() (string, error) {
	id, err := newLocalCallbackID()
	if err != nil {
		return "", err
	}
	callback := *s.callbackBase
	basePath := strings.TrimRight(callback.Path, "/")
	callback.Path = basePath + "/" + id
	callback.RawPath = ""
	return strings.TrimPrefix(callback.String(), callback.Scheme+"://"), nil
}

func (s *localCallbackServer) idFromURL(callbackURL string) string {
	parsed, err := parseCallbackURL(callbackURL)
	if err != nil {
		return ""
	}
	return s.idFromPath(parsed.EscapedPath())
}

func (s *localCallbackServer) idFromPath(path string) string {
	basePath := strings.Trim(s.callbackBase.EscapedPath(), "/")
	path = strings.Trim(path, "/")
	if basePath != "" {
		path = strings.TrimPrefix(path, basePath)
		path = strings.Trim(path, "/")
	}
	if path == "" {
		return ""
	}
	return strings.Split(path, "/")[0]
}

func (s *localCallbackServer) handle(w http.ResponseWriter, request *http.Request) {
	uniqueID := s.idFromPath(request.URL.EscapedPath())
	if uniqueID == "" {
		uniqueID = s.idFromPath(request.URL.Path)
	}

	rawRequest := dumpHTTPRequest(request)
	responseBody := []byte("ok\n")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(responseBody)
	if uniqueID == "" {
		return
	}

	remoteAddress := request.RemoteAddr
	if host, _, err := net.SplitHostPort(request.RemoteAddr); err == nil {
		remoteAddress = host
	}
	s.onInteraction(&server.Interaction{
		Protocol:      "http",
		UniqueID:      uniqueID,
		FullId:        request.Host + request.URL.EscapedPath(),
		RawRequest:    rawRequest,
		RawResponse:   "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + string(responseBody),
		RemoteAddress: remoteAddress,
		Timestamp:     time.Now(),
	})
}

func dumpHTTPRequest(request *http.Request) string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "%s %s %s\r\n", request.Method, request.URL.RequestURI(), request.Proto)
	fmt.Fprintf(&builder, "Host: %s\r\n", request.Host)
	for key, values := range request.Header {
		for _, value := range values {
			fmt.Fprintf(&builder, "%s: %s\r\n", key, value)
		}
	}
	builder.WriteString("\r\n")
	if request.Body != nil {
		body, _ := io.ReadAll(io.LimitReader(request.Body, localCallbackMaxBody))
		builder.Write(body)
	}
	return builder.String()
}

func newLocalCallbackID() (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(data[:]), nil
}
