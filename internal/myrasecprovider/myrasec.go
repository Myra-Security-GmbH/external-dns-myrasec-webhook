package myrasecprovider

import (
	"context"
	"fmt"
	"strings"
	"sync"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"go.uber.org/zap"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

const (
	defaultOwnerTag = "external-dns" // Must match --txt-owner-id in ExternalDNS
)

// MyraSecAPIClient defines the interface for interacting with the MyraSec API
type MyraSecAPIClient interface {
	ListDomains(params map[string]string) ([]myrasec.Domain, error)
	ListDNSRecords(domainId int, params map[string]string) ([]myrasec.DNSRecord, error)
	CreateDNSRecord(record *myrasec.DNSRecord, domainId int) (*myrasec.DNSRecord, error)
	UpdateDNSRecord(record *myrasec.DNSRecord, domainId int) (*myrasec.DNSRecord, error)
	DeleteDNSRecord(record *myrasec.DNSRecord, domainId int) (*myrasec.DNSRecord, error)
}

// MyraSecDNSProvider is the implementation of the MyraSec DNS provider
type MyraSecDNSProvider struct {
	provider.BaseProvider
	apiClient         MyraSecAPIClient
	logger            *zap.Logger
	domainFilter      endpoint.DomainFilter
	dryRun            bool
	domainsMu         sync.Mutex
	cachedDomains     []myrasec.Domain
	ttl               int
	owner             string
	disableProtection bool
}

// NewMyraSecDNSProvider initializes a new MyraSec DNS provider.
func NewMyraSecDNSProvider(logger *zap.Logger, providerConfig Config) (*MyraSecDNSProvider, error) {
	if providerConfig.APIKey == "" {
		return nil, fmt.Errorf("no API key provided")
	}

	if providerConfig.APISecret == "" {
		return nil, fmt.Errorf("no API secret provided")
	}

	// Initialize the MyraSec API client
	api, err := myrasec.New(
		providerConfig.APIKey,
		providerConfig.APISecret,
	)
	if err != nil {
		logger.Error("Failed to create MyraSec API client", zap.Error(err))
		return nil, fmt.Errorf("failed to create MyraSec API client: %w", err)
	}

	// Set the API language to English to ensure consistent responses
	api.Language = "en"

	provider := &MyraSecDNSProvider{
		BaseProvider:      provider.BaseProvider{},
		apiClient:         api,
		logger:            logger,
		domainFilter:      providerConfig.DomainFilter,
		dryRun:            providerConfig.DryRun,
		ttl:               providerConfig.TTL,
		owner:             defaultOwnerTag,
		disableProtection: providerConfig.DisableProtection,
	}

	return provider, nil
}

// GetDomains retrieves all domains from the MyraSec API and caches them for
// future use. Filtering happens in SelectDomains.
func (p *MyraSecDNSProvider) GetDomains() ([]myrasec.Domain, error) {
	p.domainsMu.Lock()
	defer p.domainsMu.Unlock()

	// If we have cached domains, return them
	if len(p.cachedDomains) > 0 {
		p.logger.Debug("Using cached domains", zap.Int("count", len(p.cachedDomains)))
		return p.cachedDomains, nil
	}

	p.logger.Debug("Retrieving domains from MyraSec API")
	domains, err := p.apiClient.ListDomains(map[string]string{"pageSize": "9999"})
	if err != nil {
		p.logger.Error("Failed to list domains", zap.Error(err))
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}

	p.logger.Debug("Domains retrieved", zap.Int("count", len(domains)))

	p.cachedDomains = domains
	return domains, nil
}

// SelectDomains returns all domains the provider manages, based on the
// configured domain filters. Every filter entry that does not match a domain
// in the account is logged as an error, and if no entry matches at all an
// error is returned so the provider never silently manages an unrelated
// domain. Without filters, a single-domain account uses that domain; with
// multiple domains only the first is managed, which is logged loudly.
func (p *MyraSecDNSProvider) SelectDomains() ([]myrasec.Domain, error) {
	domains, err := p.GetDomains()
	if err != nil {
		return nil, err
	}

	if len(domains) == 0 {
		p.logger.Error("No domains found in MyraSec account")
		return nil, ErrDomainNotFound
	}

	if len(p.domainFilter.Filters) == 0 {
		if len(domains) > 1 {
			p.logger.Warn("Multiple domains found but no domain filter specified. Managing only the first domain.",
				zap.String("domain", domains[0].Name),
				zap.Strings("ignored_domains", domainNames(domains[1:])),
				zap.Int("total_domains", len(domains)))
			return domains[:1], nil
		}

		p.logger.Debug("Using the only available domain",
			zap.String("domain", domains[0].Name))
		return domains, nil
	}

	domainsByName := make(map[string]myrasec.Domain, len(domains))
	for _, domain := range domains {
		domainsByName[normalizeDomainName(domain.Name)] = domain
	}

	var selected []myrasec.Domain
	seen := make(map[int]bool)
	for _, filter := range p.domainFilter.Filters {
		name := normalizeDomainName(filter)
		if name == "" {
			continue
		}

		domain, ok := domainsByName[name]
		if !ok {
			p.logger.Error("Domain filter entry does not match any domain in the MyraSec account",
				zap.String("filter", filter),
				zap.Int("available_domains", len(domains)))
			continue
		}

		if seen[domain.ID] {
			continue
		}
		seen[domain.ID] = true
		selected = append(selected, domain)

		p.logger.Debug("Using domain from filter",
			zap.String("domain", domain.Name))
	}

	if len(selected) == 0 {
		p.logger.Error("No domain filter entry matched any domain in the MyraSec account",
			zap.Strings("filters", p.domainFilter.Filters),
			zap.Int("available_domains", len(domains)))
		return nil, ErrDomainNotFound
	}

	return selected, nil
}

// normalizeDomainName canonicalizes a domain name for exact-match comparison.
func normalizeDomainName(name string) string {
	return strings.ToLower(stripTrailingDot(strings.TrimSpace(name)))
}

func domainNames(domains []myrasec.Domain) []string {
	names := make([]string, len(domains))
	for i, domain := range domains {
		names[i] = domain.Name
	}
	return names
}

// ApplyChanges applies the given changes to the MyraSec DNS records
func (p *MyraSecDNSProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	return p.ApplyChangesWithWorkers(ctx, changes)
}
