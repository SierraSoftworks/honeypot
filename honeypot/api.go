package honeypot

import (
	"net/http"

	"github.com/SierraSoftworks/girder"
	"github.com/gorilla/mux"
)

func (h *Host) RunAPI(addr string) error {
	r := mux.NewRouter()
	r.Path("/api/v1/stats").Methods("GET").Handler(girder.NewHandler(h.getState))
	r.Path("/api/v1/health").Methods("GET").Handler(girder.NewHandler(h.getHealth))

	return http.ListenAndServe(":8080", r)
}

func (h *Host) getState(c *girder.Context) (interface{}, error) {
	h.State.m.RLock()
	defer h.State.m.RUnlock()

	return h.State, nil
}

func (h *Host) getHealth(c *girder.Context) (interface{}, error) {
	return "OK", nil
}
