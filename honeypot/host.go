package honeypot

import (
	"sync"
)

type Host struct {
	State *State

	wg sync.WaitGroup
}

type ServiceHost func(record func(*Metadata))

func New() *Host {
	h := &Host{
		State: &State{
			Services: []*Service{},
		},
	}

	return h
}

func (h *Host) Wait() {
	h.wg.Wait()
}

func (h *Host) Host(name string, service ServiceHost) {
	record := func(m *Metadata) {
		h.State.Record(name, m)
	}

	h.wg.Add(1)

	go func() {
		service(record)
		h.wg.Done()
	}()
}
