package myrasecprovider

import (
	"sigs.k8s.io/external-dns/endpoint"
)

// Config is used to configure the creation of the MyraSecDNSProvider.
type Config struct {
	APIKey            string
	APISecret         string
	BaseURL           string
	DomainFilter      endpoint.DomainFilter
	DryRun            bool
	TTL               int
	DisableProtection bool
}
