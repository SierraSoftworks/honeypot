package honeypot

import (
	"net/http"
	"sync"

	"github.com/SierraSoftworks/girder"
	"github.com/gorilla/mux"
)

type Honeypot struct {
	State *State

	wg sync.WaitGroup
}

func New() *Honeypot {
	h := &Honeypot{
		State: &State{
			Services: []Service{},
		},
	}

	h.wg.Add(1)

	go func() {
		r := mux.NewRouter()
		r.Path("/api/v1/stats").Methods("GET").Handler(girder.NewHandler(h.getState))

		http.ListenAndServe(":8080", r)
		h.wg.Done()
	}()

	return h
}

func (h *Honeypot) Wait() {
	h.wg.Wait()
}

func (h *Honeypot) Host(name string, service func(record func(m *Metadata))) {
	record := func(m *Metadata) {
		h.State.Record(name, m)
	}

	h.wg.Add(1)

	go func() {
		service(record)
		h.wg.Done()
	}()
}

func (h *Honeypot) getState(c *girder.Context) (interface{}, error) {
	return h.State, nil
}
