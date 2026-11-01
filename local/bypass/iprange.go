package localbypass

import (
	"fmt"
	"strconv"
)

// ip list must in order for matching
var subnetIp4RangeList = []uint32{
	0, 1, // 0.0.0.0/32
	167772160, 184549376, // 10.0.0.0/8
	2130706432, 2147483648, // 127.0.0.0/8
	2886729728, 2887778304, // 172.16.0.0/12
	3232235520, 3232301056, // 192.168.0.0/16
}

// var subnetIp6RangeList = [][]uint32{
// 	[]uint32{0x0, 0x0, 0x0, 0x0}, []uint32{0x0, 0x0, 0x0, 0x2}, // ::/127
// 	[]uint32{0xfe800000, 0x0, 0x0, 0x0}, []uint32{0xfe800000, 0x1, 0x0, 0x0}, // fe80::/64
// 	[]uint32{0xfec00000, 0x0, 0x0, 0x0}, []uint32{0xfec00000, 0x10000, 0x0, 0x0}, // fec0::/48
// }

var errNotIP4 = fmt.Errorf("not ip4")

// var errNotIP6 = fmt.Errorf("not ip6")

func isLocalIp4(ip uint32) bool {
	left := 0
	right := len(subnetIp4RangeList) - 1

	for left < right {
		mid := (left + right) / 2

		var lv, rv uint32
		if (mid & 0x01) != 0 {
			lv = subnetIp4RangeList[mid-1]
			rv = subnetIp4RangeList[mid]
			if ip >= lv {
				if ip < rv {
					return true
				} else {
					left = mid + 1
				}
			} else {
				right = mid - 2
			}
		} else {
			lv = subnetIp4RangeList[mid]
			rv = subnetIp4RangeList[mid+1]

			if ip >= lv {
				if ip < rv {
					return true
				} else {
					left = mid + 2
				}
			} else {
				right = mid - 1
			}
		}
	}
	return false
}

func string2IP4(domainName string) (uint32, error) {
	dots := domainDots(domainName)
	if len(dots) != 3 {
		return 0, errNotIP4
	}

	// append last position
	dots = append(dots, len(domainName))

	var ip uint32
	p1 := 0
	for i := 0; i < 4; i++ {
		p2 := dots[i]
		part := domainName[p1:p2]
		p, err := strconv.Atoi(part)
		if err != nil {
			return 0, errNotIP4
		}

		if p < 0 || p > 255 {
			return 0, errNotIP4
		}

		ip = ip << 8
		ip = ip | (uint32(p))
		p1 = p2 + 1
	}

	return ip, nil
}

func isStringLocalIP4(domainName string) bool {
	ip4, err := string2IP4(domainName)
	if err != nil {
		return false
	}

	return isLocalIp4(ip4)
}

func domainDots(domainName string) []int {
	dots := make([]int, 0, 8)
	for i := 0; i < len(domainName); i++ {
		if domainName[i] == '.' {
			dots = append(dots, i)
		}
	}

	return dots
}

func isDomainIn(domainName string, donameMap map[string]struct{}) bool {
	domainDots := domainDots(domainName)

	for i := len(domainDots) - 1; i >= 0; i-- {
		dot := domainDots[i]
		part := domainName[dot+1:]
		if _, ok := donameMap[part]; ok {
			return true
		}
	}

	if _, ok := donameMap[domainName]; ok {
		return true
	}

	return false
}
