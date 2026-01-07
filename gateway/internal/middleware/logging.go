package middleware

import (
	"log"
	"net/http"
	"time"
)

// ResponseWriterWrapper allows us to capture the status code
type ResponseWriterWrapper struct {
	http.ResponseWriter
	StatusCode int
}

// WriteHeader captures the status code
func (w *ResponseWriterWrapper) WriteHeader(code int) {
	w.StatusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// RequestLogger logs every request
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap the ResponseWriter
		wrappedWriter := &ResponseWriterWrapper{
			ResponseWriter: w,
			StatusCode:     http.StatusOK, // Default to 200
		}

		// Process request
		next.ServeHTTP(wrappedWriter, r)

		// Calculate duration
		duration := time.Since(start)

		// Log the details
		// Format: [STATUS] METHOD PATH | IP | DURATION
		log.Printf(
			"[%d] %s %s | %s | %v",
			wrappedWriter.StatusCode,
			r.Method,
			r.URL.Path,
			r.RemoteAddr,
			duration,
		)
	})
}