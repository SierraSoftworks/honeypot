package honeypot

import (
	"log"
	"sync"
)

type State struct {
	Services []*Service `json:"services"`

	m sync.RWMutex
}

type Service struct {
	Name string `json:"name"`

	Attempts    uint64            `json:"attempts"`
	Credentials map[string]uint64 `json:"credentials"`
	Resources   map[string]uint64 `json:"resources"`
	Sources     map[string]uint64 `json:"sources"`
	Features    map[string]uint64 `json:"features"`
}

type Metadata struct {
	Credentials   string
	Resources     []string
	SourceAddress string
	Features      []string
}

func (s *State) Record(service string, m *Metadata) {
	s.m.Lock()
	defer s.m.Unlock()

	for _, svc := range s.Services {
		if svc.Name == service {
			svc.Record(m)
			return
		}
	}

	svc := &Service{
		Name:        service,
		Attempts:    0,
		Credentials: map[string]uint64{},
		Resources:   map[string]uint64{},
		Sources:     map[string]uint64{},
		Features:    map[string]uint64{},
	}

	svc.Record(m)

	s.Services = append(s.Services, svc)
}

func (s *Service) Record(m *Metadata) {
	s.Attempts++

	if m.Credentials != "" {
		s.Credentials[m.Credentials]++
	}

	if m.Resources != nil {
		for _, r := range m.Resources {
			s.Resources[r]++
		}
	}

	if m.SourceAddress != "" {
		s.Sources[m.SourceAddress]++
	}

	if m.Features != nil {
		for _, f := range m.Features {
			s.Features[f]++
		}
	}

	log.Printf("%s: New access attempt from [%s] for [%s] using [%s]", s.Name, m.SourceAddress, m.Resources, m.Credentials)
}
