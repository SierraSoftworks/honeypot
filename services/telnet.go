package services

import (
	"bufio"
	"log"
	"net"

	"github.com/sierrasoftworks/ssh-honeypot/honeypot"
)

func Telnet(addr string) honeypot.ServiceHost {
	return func(record func(m *honeypot.Metadata)) {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Println("Failed to start Telnet server: ", err)
			return
		}

		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Println("Failed to accept new Telnet connection: ", err)
				continue
			}

			go telnetHandle(conn, record)
		}
	}
}

func telnetHandle(conn net.Conn, record func(m *honeypot.Metadata)) {
	scanner := bufio.NewScanner(conn)
	scanner.Split(bufio.ScanLines)

	info := &honeypot.Metadata{
		SourceAddress: getIPAddress(conn.RemoteAddr()),
	}

	conn.Write([]byte("login: "))
	if scanner.Scan() {
		info.Credentials = scanner.Text() + ":"

		conn.Write([]byte("password: "))
		if scanner.Scan() {
			info.Credentials = info.Credentials + scanner.Text()
		}
	}

	conn.Close()

	record(info)
}
