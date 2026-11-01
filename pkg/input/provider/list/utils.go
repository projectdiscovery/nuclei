package list

type ipOptions struct {
	ScanAllIPs bool
	IPV4       bool
	IPV6       bool
	Auto       bool // -iv omitted: prefer IPv6, fall back to IPv4
}
