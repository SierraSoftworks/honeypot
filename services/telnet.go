package services

import (
	"bufio"
	"log"
	"net"
	"time"

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
	defer conn.Close()

	info := &honeypot.Metadata{
		SourceAddress: getIPAddress(conn.RemoteAddr()),
		Resources:     []string{},
	}
	defer record(info)

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, _ := capturePayload(conn, info)
	if n == 0 {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		scanner := bufio.NewScanner(conn)
		scanner.Split(bufio.ScanLines)

		conn.Write([]byte("login: "))
		if scanner.Scan() {
			info.Credentials = scanner.Text() + ":"

			conn.Write([]byte("password: "))
			if scanner.Scan() {
				info.Credentials = info.Credentials + scanner.Text()
			}
		}
	}

}
