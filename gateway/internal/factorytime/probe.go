package factorytime

import (
	"context"
	"errors"
	"net/http"
)

type SchemaVerifier interface {
	VerifySchema() error
}

type SignerReadiness interface {
	Ready(context.Context) error
}

type probeHandler struct {
	database SchemaVerifier
	signer   SignerReadiness
}

func NewProbeHandler(database SchemaVerifier,
	signer SignerReadiness) (http.Handler, error) {
	if database == nil || signer == nil {
		return nil, errors.New("factory-time readiness dependencies are required")
	}
	return &probeHandler{database: database, signer: signer}, nil
}

func (handler *probeHandler) ServeHTTP(writer http.ResponseWriter,
	request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if request.Method != http.MethodGet || request.URL.RawQuery != "" ||
		request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	switch request.URL.Path {
	case "/healthz":
		writer.WriteHeader(http.StatusNoContent)
	case "/readyz":
		if err := handler.database.VerifySchema(); err != nil {
			writer.Header().Set("Retry-After", "1")
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if err := handler.signer.Ready(request.Context()); err != nil {
			writer.Header().Set("Retry-After", "1")
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	default:
		writer.WriteHeader(http.StatusNotFound)
	}
}
