package services

import (
	"bufio"
	"crypto/md5"
	"fmt"
	"io"
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

	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	eager := make([]byte, 256)

	if n, err := conn.Read(eager); err == nil {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))

		if n > 0 && isText(string(eager[:n])) {
			suffix := ""
			if n == 256 {
				suffix = "..."
			}
			info.Resources = append(info.Resources, string(eager[:n])+suffix)
		}

		hash := md5.New()
		hash.Write(eager[:n])

		io.Copy(hash, conn)

		info.Resources = append(info.Resources, fmt.Sprintf("md5:%x", md5.Sum([]byte{})))
		return
	} else {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))

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
