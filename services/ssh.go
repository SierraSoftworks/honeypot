package services

import (
	"encoding/base64"
	"fmt"

	"github.com/gliderlabs/ssh"
	"github.com/sierrasoftworks/ssh-honeypot/honeypot"
)

func SSH(addr string) honeypot.ServiceHost {
	return func(record func(m *honeypot.Metadata)) {
		ssh.ListenAndServe(addr, func(s ssh.Session) {

		}, ssh.PasswordAuth(func(ctx ssh.Context, password string) bool {
			record(&honeypot.Metadata{
				SourceAddress: getIPAddress(ctx.RemoteAddr()),
				Credentials:   fmt.Sprintf("%s:%s", ctx.User(), password),
				Features: []string{
					ctx.ClientVersion(),
				},
			})

			return false
		}), ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
			record(&honeypot.Metadata{
				SourceAddress: getIPAddress(ctx.RemoteAddr()),
				Credentials:   fmt.Sprintf("%s:%s %s", ctx.User(), key.Type(), base64.RawStdEncoding.EncodeToString(key.Marshal()[len(key.Type()):])),
				Features: []string{
					ctx.ClientVersion(),
				},
			})

			return false
		}))
	}
}
