package honeypot

import (
	"log"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	requestCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "honeypot_requests_count",
		Help: "The number of requests which have been made to the honeypot by external clients.",
	}, []string{
		"service",
		"source",
	})

	credentialsCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "honeypot_credentials_count",
		Help: "The number of times that a specific set of credentials were used to communicate with the honeypot.",
	}, []string{
		"service",
		"credentials",
	})

	featuresCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "honeypot_features_count",
		Help: "The number of times that a specific identifying feature has been tracked in requests to the honeypot.",
	}, []string{
		"service",
		"feature",
	})

	resourcesCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "honeypot_resources_count",
		Help: "The number of times that a specific resources was requested or sent in requests to the honeypot.",
	}, []string{
		"service",
		"resource",
	})
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
	recordMetrics(service, m)

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

func recordMetrics(service string, m *Metadata) {
	requestCount.WithLabelValues(service, m.SourceAddress).Inc()

	if m.Credentials != "" {
		credentialsCount.WithLabelValues(service, m.Credentials).Inc()
	}

	if m.Features != nil {
		for _, f := range m.Features {
			featuresCount.WithLabelValues(service, f).Inc()
		}
	}

	if m.Resources != nil {
		for _, r := range m.Resources {
			resourcesCount.WithLabelValues(service, r).Inc()
		}
	}
}
