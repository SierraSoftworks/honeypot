package honeypot

import "log"

type State struct {
	Services []Service `json:"services"`
}

type Service struct {
	Name string `json:"name"`

	Attempts    uint64            `json:"attempts"`
	Credentials map[string]uint64 `json:"credentials"`
	Resources   map[string]uint64 `json:"resources"`
	Sources     map[string]uint64 `json:"sources"`
}

type Metadata struct {
	Credentials   string
	Resource      string
	SourceAddress string
}

func (s *State) Record(service string, m *Metadata) {
	for _, svc := range s.Services {
		if svc.Name == service {
			svc.Record(m)
			return
		}
	}

	svc := Service{
		Name:        service,
		Attempts:    0,
		Credentials: map[string]uint64{},
		Resources:   map[string]uint64{},
		Sources:     map[string]uint64{},
	}

	svc.Record(m)

	s.Services = append(s.Services, svc)
}

func (s *Service) Record(m *Metadata) {
	s.Attempts++

	if m.Credentials != "" {
		s.Credentials[m.Credentials]++
	}

	if m.Resource != "" {
		s.Resources[m.Resource]++
	}

	if m.SourceAddress != "" {
		s.Sources[m.SourceAddress]++
	}

	log.Printf("%s: New access attempt from [%s] for [%s] using [%s]", s.Name, m.SourceAddress, m.Resource, m.Credentials)
}
