package main

import (
	"log"

	"github.com/sierrasoftworks/ssh-honeypot/honeypot"
	"github.com/sierrasoftworks/ssh-honeypot/services"
)

func main() {
	hp := honeypot.New()

	hp.Host("ssh", services.SSH(":2222"))
	hp.Host("telnet", services.Telnet(":2323"))
	hp.Host("rdp", services.Tcp(":3389"))
	hp.Host("vnc", services.Tcp(":5900"))

	hp.Host("http", services.Http(":8081"))

	hp.Host("redis", services.Tcp(":6379"))
	hp.Host("postgres", services.Tcp(":5432"))
	hp.Host("mysql", services.Tcp(":3306"))
	hp.Host("mongodb", services.Tcp(":27017"))

	log.Println("Starting Honeypot server on :8080")
	hp.RunAPI(":8080")

	log.Println("Waiting for honeypots to shutdown")
	hp.Wait()
}
