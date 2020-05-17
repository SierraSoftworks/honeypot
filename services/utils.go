package services

import (
	"net"
	"strings"
)

func getIPAddress(addr net.Addr) string {
	parts := strings.Split(addr.String(), ":")

	return strings.Join(parts[:len(parts)-1], ":")
}

func getIPAddressFromString(addr string) string {
	parts := strings.Split(addr, ":")

	return strings.Join(parts[:len(parts)-1], ":")
}
