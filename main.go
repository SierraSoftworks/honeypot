package main

import (
	"log"

	"github.com/sierrasoftworks/ssh-honeypot/honeypot"
	"github.com/sierrasoftworks/ssh-honeypot/services"
)

func main() {
	hp := honeypot.New()

	hp.Host("ssh", services.SSH)

	log.Println("Started Honeypot server on :8080")
	hp.Wait()
}
