package services

import (
	"net"
	"strings"
	"unicode"
)

func getIPAddress(addr net.Addr) string {
	parts := strings.Split(addr.String(), ":")

	return strings.Join(parts[:len(parts)-1], ":")
}

func getIPAddressFromString(addr string) string {
	parts := strings.Split(addr, ":")

	return strings.Join(parts[:len(parts)-1], ":")
}

func isText(s string) bool {
	for _, c := range s {
		if c > unicode.MaxLatin1 {
			return false
		}
	}

	return true
}
