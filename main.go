package main

import (
	"github.com/sierrasoftworks/ssh-honeypot/honeypot"
	"github.com/sierrasoftworks/ssh-honeypot/services"
)

func main() {
	hp := honeypot.New()

	hp.Host("ssh", services.SSH)

	hp.Wait()
}
