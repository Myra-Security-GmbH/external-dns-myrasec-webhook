package api

const (
	MediaTypeFormatAndVersion = "application/external.dns.webhook+json;version=1"
	contentTypeHeader         = "Content-Type"
	contentTypePlaintext      = "text/plain"
	varyHeader                = "Vary"
	logFieldError             = "err"
)

type Message struct {
	Message string `json:"message"`
}

// endpointsRequest represents the request body for the AdjustEndpoints endpoint
type endpointsRequest struct {
	Endpoints []dnsEndpoint `json:"endpoints"`
}

// dnsEndpoint represents a DNS endpoint in the request
type dnsEndpoint struct {
	DNSName    string   `json:"dnsName"`
	RecordType string   `json:"recordType"`
	Targets    []string `json:"targets"`
	RecordTTL  int64    `json:"recordTTL"`
}
