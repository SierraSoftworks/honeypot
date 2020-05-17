package services

import (
	"encoding/base64"
	"log"
	"net/http"
	"strings"

	"github.com/sierrasoftworks/ssh-honeypot/honeypot"
)

func Http(addr string) honeypot.ServiceHost {
	return func(record func(m *honeypot.Metadata)) {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			creds := ""

			if auth := r.Header.Get("Authorization"); auth != "" {
				if strings.HasPrefix(auth, "Basic ") {
					if c, err := base64.RawStdEncoding.DecodeString(auth[len("Basic "):]); err == nil {
						creds = string(c)
					} else {
						log.Println("Failed to parse HTTP Basic credentials: ", err)
					}
				} else {
					creds = auth
				}
			}

			record(&honeypot.Metadata{
				SourceAddress: r.RemoteAddr,
				Credentials:   creds,
				Resource:      r.Method + " " + r.URL.String(),
				Features: []string{
					r.Header.Get("User-Agent"),
				},
			})

			w.Header().Add("WWW-Authenticate", `Basic realm="Admin Portal", charset="UTF-8"`)
			w.WriteHeader(401)
		})

		http.ListenAndServe(addr, mux)
	}
}
