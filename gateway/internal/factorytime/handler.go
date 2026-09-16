package factorytime

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strconv"
)

type Handler struct {
	authority *Authority
}

func NewHandler(authority *Authority) (*Handler, error) {
	if authority == nil {
		return nil, ErrInvalid
	}
	return &Handler{authority: authority}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter,
	request *http.Request) {
	setResponseHeaders(writer.Header())
	if handler == nil || handler.authority == nil || request == nil ||
		request.Method != http.MethodPost || request.URL.Path != EndpointPath ||
		request.URL.RawPath != "" || request.URL.RawQuery != "" ||
		request.URL.Fragment != "" || !verifiedStationTLS(request) ||
		singleHeader(request.Header, "Content-Type") != "application/json" ||
		singleHeader(request.Header, "Accept") != "application/json" ||
		singleHeader(request.Header, "Cache-Control") != "no-store" ||
		len(request.Header.Values("Content-Encoding")) != 0 ||
		request.ContentLength <= 0 || request.ContentLength > MaximumRequestBytes ||
		len(request.TransferEncoding) != 0 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, MaximumRequestBytes+1))
	if err != nil || int64(len(body)) != request.ContentLength ||
		len(body) > MaximumRequestBytes {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	input, requestDigest, err := ParseRequest(body)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	response, err := handler.authority.Issue(request.Context(), input,
		requestDigest, request.TLS.PeerCertificates[0].Raw)
	if err != nil {
		switch {
		case errors.Is(err, ErrUnauthorized), errors.Is(err, ErrOutsideWindow):
			writer.WriteHeader(http.StatusForbidden)
		case errors.Is(err, ErrReplay):
			writer.WriteHeader(http.StatusConflict)
		case errors.Is(err, ErrInvalid):
			writer.WriteHeader(http.StatusBadRequest)
		default:
			writer.Header().Set("Retry-After", "1")
			writer.WriteHeader(http.StatusServiceUnavailable)
		}
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Content-Length", strconv.Itoa(len(response)))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(response)
}

func verifiedStationTLS(request *http.Request) bool {
	return request.TLS != nil && request.TLS.Version == tls.VersionTLS13 &&
		len(request.TLS.PeerCertificates) > 0 &&
		len(request.TLS.PeerCertificates[0].Raw) > 0 &&
		len(request.TLS.VerifiedChains) > 0 &&
		len(request.TLS.VerifiedChains[0]) > 0 &&
		request.TLS.PeerCertificates[0].Equal(
			request.TLS.VerifiedChains[0][0])
}

func setResponseHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
}

func singleHeader(header http.Header, name string) string {
	values := header.Values(name)
	if len(values) != 1 {
		return ""
	}
	return values[0]
}
