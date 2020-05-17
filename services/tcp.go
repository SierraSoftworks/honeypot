package services

import (
	"bufio"
	"log"
	"net"

	"github.com/sierrasoftworks/ssh-honeypot/honeypot"
)

func Tcp(addr string) honeypot.ServiceHost {
	return func(record func(m *honeypot.Metadata)) {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Println("Failed to start TCP server: ", err)
			return
		}

		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Println("Failed to accept new TCP connection: ", err)
				continue
			}

			go tcpHandle(conn, record)
		}
	}
}

func tcpHandle(conn net.Conn, record func(m *honeypot.Metadata)) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	scanner.Split(bufio.ScanLines)

	record(&honeypot.Metadata{
		SourceAddress: getIPAddress(conn.RemoteAddr()),
	})

}
