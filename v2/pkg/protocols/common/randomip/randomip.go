package randomip

import (
	"crypto/rand"
	"net"

	"github.com/pkg/errors"
	iputil "github.com/projectdiscovery/utils/ip"
	randutil "github.com/projectdiscovery/utils/rand"
)

const (
	maxIterations = 255
)

func GetRandomIPWithCidr(cidrs ...string) (net.IP, error) {
	if len(cidrs) == 0 {
		return nil, errors.Errorf("must specify at least one cidr")
	}

	randIdx, err := randutil.IntN(len(cidrs))
	if err != nil {
		return nil, err
	}

	cidr := cidrs[randIdx]

	if !iputil.IsCIDR(cidr) {
		return nil, errors.Errorf("%s is not a valid cidr", cidr)
	}

	baseIp, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	switch {
	case 255 == ipnet.Mask[len(ipnet.Mask)-1]:
		return baseIp, nil
	case iputil.IsIPv4(baseIp.String()):
		return getRandomIP(ipnet, 4), nil
	case iputil.IsIPv6(baseIp.String()):
		return getRandomIP(ipnet, 16), nil
	default:
		return nil, errors.New("invalid base ip")
	}
}

func getRandomIP(ipnet *net.IPNet, size int) net.IP {
	ip := ipnet.IP
	var iteration int

	for iteration < maxIterations {
		iteration++
		ones, _ := ipnet.Mask.Size()
		quotient := ones / 8
		remainder := ones % 8
		var r []byte
		switch size {
		case 4, 16:
			r = make([]byte, size)
		default:
			return ip
		}

		_, _ = rand.Read(r)

		for i := 0; i <= quotient; i++ {
			if i == quotient {
				shifted := byte(r[i]) >> remainder
				r[i] = ipnet.IP[i] + (^ipnet.IP[i] & shifted)
			} else {
				r[i] = ipnet.IP[i]
			}
		}

		ip = r

		if !ip.Equal(ipnet.IP) {
			break
		}
	}

	return ip
}
