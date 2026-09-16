package accountauth

import (
	"errors"
	"net/http"
)

// SchemaVerifier is the narrow readiness dependency exposed to the probe
// listener. It never grants access to account or token data.
type SchemaVerifier interface {
	VerifySchema() error
}

type probeHandler struct {
	verifier SchemaVerifier
}

// NewProbeHandler returns the credential-free handler intended only for the
// dedicated Kubernetes probe port. NetworkPolicy must not expose this port as
// an account API.
func NewProbeHandler(verifier SchemaVerifier) (http.Handler, error) {
	if verifier == nil {
		return nil, errors.New("probe schema verifier is required")
	}
	return &probeHandler{verifier: verifier}, nil
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
		if err := handler.verifier.VerifySchema(); err != nil {
			writer.Header().Set("Retry-After", "1")
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	default:
		writer.WriteHeader(http.StatusNotFound)
	}
}
