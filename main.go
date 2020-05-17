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

	log.Println("Starting Honeypot server on :8080")
	hp.RunAPI(":8080")

	log.Println("Waiting for honeypots to shutdown")
	hp.Wait()
}
