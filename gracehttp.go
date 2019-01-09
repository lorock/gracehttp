package gracehttp

import (
	"net/http"
	"time"
)

const (
	// DefaultReadTimeout DefaultReadTimeout
	DefaultReadTimeout = 60 * time.Second
	// DefaultWriteTimeout DefaultWriteTimeout
	DefaultWriteTimeout = DefaultReadTimeout
)

// ListenAndServe refer http.ListenAndServe
func ListenAndServe(addr string, handler http.Handler) error {
	return NewServer(addr, handler, DefaultReadTimeout, DefaultWriteTimeout).ListenAndServe()
}

// ListenAndServeTLS refer http.ListenAndServeTLS
func ListenAndServeTLS(addr string, certFile string, keyFile string, handler http.Handler) error {
	return NewServer(addr, handler, DefaultReadTimeout, DefaultWriteTimeout).ListenAndServeTLS(certFile, keyFile)
}
