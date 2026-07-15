package httpserver

import (
	"encoding/json"
	"net/http"
)

// problem is an RFC 7807 error body; the web client reads title and
// detail.
type problem struct {
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	Status int    `json:"status"`
}

func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem{Title: title, Detail: detail, Status: status})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// decodeJSON enforces a small body and strict field names.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeProblem(w, http.StatusBadRequest, "Malformed request body", err.Error())
		return false
	}
	return true
}
