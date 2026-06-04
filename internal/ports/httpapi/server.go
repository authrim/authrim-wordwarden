package httpapi

import (
	"encoding/json"
	"net/http"
)

type healthResponse struct {
	OK        bool   `json:"ok"`
	Connector string `json:"connector"`
	Version   string `json:"version"`
}

func NewHandler(version string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, healthResponse{
			OK:        true,
			Connector: "authrim-wordwarden",
			Version:   version,
		})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
