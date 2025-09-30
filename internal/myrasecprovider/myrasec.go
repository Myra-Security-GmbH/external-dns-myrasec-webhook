package myrasecprovider

import (
	"context"
	"fmt"
	"strconv"

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
	apiClient     MyraSecAPIClient
	logger        *zap.Logger
	domainFilter  endpoint.DomainFilter
	domainId      string
	domainName    string
	dryRun        bool
	cachedDomains []myrasec.Domain
	ttl           int
	owner         string
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
		BaseProvider: provider.BaseProvider{},
		apiClient:    api,
		logger:       logger,
		domainFilter: providerConfig.DomainFilter,
		dryRun:       providerConfig.DryRun,
		ttl:          providerConfig.TTL,
		owner:        defaultOwnerTag,
	}

	return provider, nil
}

// GetDomains retrieves all domains from the MyraSec API and applies filtering if configured
// It also caches the domains for future use
func (p *MyraSecDNSProvider) GetDomains() ([]myrasec.Domain, error) {
	// If we have cached domains, return them
	if len(p.cachedDomains) > 0 {
		p.logger.Debug("Using cached domains", zap.Int("count", len(p.cachedDomains)))
		return p.cachedDomains, nil
	}

	p.logger.Debug("Retrieving domains from MyraSec API")
	domains, err := p.apiClient.ListDomains(nil)
	if err != nil {
		p.logger.Error("Failed to list domains", zap.Error(err))
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}

	p.logger.Debug("Domains retrieved", zap.Int("count", len(domains)))

	// Filter domains if domain filter is configured
	if len(p.domainFilter.Filters) > 0 {
		var filteredDomains []myrasec.Domain
		for _, domain := range domains {
			if p.domainFilter.Match(domain.Name) {
				filteredDomains = append(filteredDomains, domain)
			}
		}

		if len(filteredDomains) == 0 {
			p.logger.Warn("No domains match the configured filters",
				zap.Strings("filters", p.domainFilter.Filters),
				zap.Int("available_domains", len(domains)))
			// Return all domains but with a warning
			p.cachedDomains = domains
			return domains, nil
		}

		p.logger.Debug("Filtered domains",
			zap.Int("filtered_count", len(filteredDomains)),
			zap.Int("total_count", len(domains)))

		// Cache the filtered domains
		p.cachedDomains = filteredDomains
		return filteredDomains, nil
	}

	// Cache all domains if no filter is applied
	p.cachedDomains = domains
	return domains, nil
}

// SelectDomain chooses the appropriate domain based on filters and available domains
// It returns the selected domain and sets the provider's domainId and domainName
func (p *MyraSecDNSProvider) SelectDomain() (*myrasec.Domain, error) {
	domains, err := p.GetDomains()
	if err != nil {
		return nil, err
	}

	if len(domains) == 0 {
		p.logger.Error("No domains found in MyraSec account")
		return nil, ErrDomainNotFound
	}

	var selectedDomain *myrasec.Domain

	// If we have domain filters, try to find a matching domain
	if len(p.domainFilter.Filters) > 0 {
		filterName := p.domainFilter.Filters[0]
		for _, domain := range domains {
			if domain.Name == filterName {
				selectedDomain = &domain
				p.logger.Debug("Using domain from filter",
					zap.String("domain", domain.Name))
				break
			}
		}

		// If no exact match found but we have domains, use the first one with a warning
		if selectedDomain == nil && len(domains) > 0 {
			selectedDomain = &domains[0]
			p.logger.Warn("No exact match for domain filter, using first available domain",
				zap.String("filter", filterName),
				zap.String("selected_domain", selectedDomain.Name))
		}
	} else if len(domains) == 1 {
		// If there's only one domain, use it
		selectedDomain = &domains[0]
		p.logger.Debug("Using the only available domain",
			zap.String("domain", selectedDomain.Name))
	} else if len(domains) > 1 {
		// If there are multiple domains and no filter, use the first one but log a warning
		selectedDomain = &domains[0]
		p.logger.Warn("Multiple domains found but no domain filter specified. Using the first domain.",
			zap.String("domain", selectedDomain.Name),
			zap.Int("total_domains", len(domains)))
	}

	if selectedDomain == nil {
		p.logger.Error("Failed to select a domain")
		return nil, ErrDomainNotFound
	}

	// Set the domain ID and name in the provider
	p.domainId = strconv.Itoa(selectedDomain.ID)
	p.domainName = selectedDomain.Name

	p.logger.Debug("Selected domain",
		zap.String("domain_name", selectedDomain.Name),
		zap.String("domain_id", p.domainId))

	return selectedDomain, nil
}

// ApplyChanges applies the given changes to the MyraSec DNS records
func (p *MyraSecDNSProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	return p.ApplyChangesWithWorkers(ctx, changes)
}
