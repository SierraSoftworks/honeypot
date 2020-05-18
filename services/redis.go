package services

import (
	"bufio"
	"log"
	"net"
	"strings"

	"github.com/sierrasoftworks/ssh-honeypot/honeypot"
)

func Redis(addr string) honeypot.ServiceHost {
	return func(record func(m *honeypot.Metadata)) {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Println("Failed to start Redis server: ", err)
			return
		}

		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Println("Failed to accept new Redis connection: ", err)
				continue
			}

			go redisHandle(conn, record)
		}
	}
}

func redisHandle(conn net.Conn, record func(m *honeypot.Metadata)) {
	defer conn.Close()

	meta := &honeypot.Metadata{
		SourceAddress: getIPAddress(conn.RemoteAddr()),
		Resources:     []string{},
	}
	defer record(meta)

	scanner := bufio.NewScanner(conn)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		meta.Resources = append(meta.Resources, strings.TrimSpace(scanner.Text()))

		conn.Write([]byte("-$-1\r\n"))
	}
}
