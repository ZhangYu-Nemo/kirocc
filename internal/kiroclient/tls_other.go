//go:build !darwin

package kiroclient

import "net/http"

func configureKiroTLSTransport(*http.Transport) {}
