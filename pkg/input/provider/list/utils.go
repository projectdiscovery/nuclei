package list

type ipOptions struct {
	ScanAllIPs bool
	IPV4       bool
	IPV6       bool
	Auto       bool // -iv omitted: prefer the first AAAA, otherwise an unpinned IPv4 input
}
