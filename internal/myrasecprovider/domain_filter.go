package myrasecprovider

import "sigs.k8s.io/external-dns/endpoint"

// GetDomainFilter returns the domain filter for the provider
func (d *MyraSecDNSProvider) GetDomainFilter() endpoint.DomainFilterInterface {
	return d.domainFilter
}
