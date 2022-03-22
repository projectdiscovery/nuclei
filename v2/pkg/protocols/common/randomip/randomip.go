package randomip

import (
	"math/rand"
	"net"
	"strings"
)

func IPFromRange(cidr string) (ip string) {

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}

	var ipAddr net.IP

	if ipnet.IP.To4() != nil {
		ipAddr = getRandomIP(ipnet, true, false)
	}
	if strings.Contains(ipnet.IP.String(), ":") {
		ipAddr = getRandomIP(ipnet, false, true)
	}

	return ipAddr.String()
}

func getRandomIP(ipnet *net.IPNet, ipv4, ipv6 bool) (ip net.IP) {

GENERATE:
	ones, _ := ipnet.Mask.Size()
	quotient := ones / 8
	remainder := ones % 8
	var r []byte
	if ipv4 {
		r = make([]byte, 4)
	} else if ipv6 {
		r = make([]byte, 16)
	} else {
		return ip
	}

	rand.Read(r)

	for i := 0; i <= quotient; i++ {
		if i == quotient {
			shifted := byte(r[i]) >> remainder
			r[i] = ^ipnet.IP[i] & shifted
		} else {
			r[i] = ipnet.IP[i]
		}
	}

	if ipv4 {
		ip = net.IP{r[0], r[1], r[2], r[3]}
	} else {
		ip = net.IP{r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7],
			r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]}
	}

	if ip.Equal(ipnet.IP) {
		goto GENERATE
	}

	return ip
}
