package middleware

import (
	"log"
	"net/http"
	"time"
)

type statusRecorder struct {
	http.ResponseWriter
	Status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.Status = status
	r.ResponseWriter.WriteHeader(status)
}

// [CRITICAL FIX] Implement Flush so SSEHandler can use it
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, Status: 200}
		
		next.ServeHTTP(recorder, r)

		log.Printf("[%s] %s %s %d %s", r.Method, r.RequestURI, r.RemoteAddr, recorder.Status, time.Since(start))
	})
}