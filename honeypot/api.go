package honeypot

import (
	"net/http"

	"github.com/SierraSoftworks/girder"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func (h *Host) RunAPI(addr string) error {
	r := mux.NewRouter()
	r.Path("/api/v1/stats").Methods("GET").Handler(girder.NewHandler(h.getStats))
	r.Path("/api/v1/counts").Methods("GET").Handler(girder.NewHandler(h.getCounts))
	r.Path("/api/v1/health").Methods("GET").Handler(girder.NewHandler(h.getHealth))
	r.Path("/statz").Methods("GET").Handler(promhttp.Handler())

	return http.ListenAndServe(":8080", r)
}

func (h *Host) getStats(c *girder.Context) (interface{}, error) {
	h.State.m.RLock()
	defer h.State.m.RUnlock()

	return h.State, nil
}

func (h *Host) getCounts(c *girder.Context) (interface{}, error) {
	h.State.m.RLock()
	defer h.State.m.RUnlock()

	out := map[string]uint64{}

	for _, svc := range h.State.Services {
		out[svc.Name] = svc.Attempts
		out["_total"] += svc.Attempts
	}

	return out, nil
}

func (h *Host) getHealth(c *girder.Context) (interface{}, error) {
	return "OK", nil
}
