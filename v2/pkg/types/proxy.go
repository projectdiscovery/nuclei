package types

const (
	HTTP_PROXY_ENV = "HTTP_PROXY"
	SOCKS5         = "socks5"
	HTTP           = "http"
	HTTPS          = "https"
)

var (
	// ProxyURL is the URL for the proxy server
	ProxyURL string
	// ProxySocksURL is the URL for the proxy socks server
	ProxySocksURL string
)
