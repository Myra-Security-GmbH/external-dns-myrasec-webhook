package myrasecprovider

import (
	"context"
	"testing"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/provider"
)

const testOwnerTXT = "heritage=external-dns,external-dns/owner=test-owner"

func newTestProvider(mockClient *MockMyraSecClient, filters []string) *MyraSecDNSProvider {
	return &MyraSecDNSProvider{
		BaseProvider: provider.BaseProvider{},
		apiClient:    mockClient,
		logger:       zap.NewNop(),
		domainFilter: endpoint.DomainFilter{Filters: filters},
		ttl:          300,
		owner:        "test-owner",
	}
}

// findEndpoint returns the endpoints matching the given name and type.
func findEndpoints(endpoints []*endpoint.Endpoint, dnsName, recordType string) []*endpoint.Endpoint {
	var found []*endpoint.Endpoint
	for _, ep := range endpoints {
		if ep.DNSName == dnsName && ep.RecordType == recordType {
			found = append(found, ep)
		}
	}
	return found
}

// TestRecordsGroupsMultipleValues verifies that multiple raw records with the
// same (name, type) are collapsed into a single endpoint with all values as
// targets, while TXT ownership records keep their per-name handling.
func TestRecordsGroupsMultipleValues(t *testing.T) {
	mockClient := new(MockMyraSecClient)

	domains := []myrasec.Domain{{ID: 123, Name: "example.com"}}
	mockClient.On("ListDomains", mock.Anything).Return(domains, nil)

	records := []myrasec.DNSRecord{
		{ID: 1, Name: "app.example.com", Value: testOwnerTXT, RecordType: "TXT", TTL: 300},
		{ID: 2, Name: "app.example.com", Value: "10.100.0.1", RecordType: "A", TTL: 300},
		{ID: 3, Name: "app.example.com", Value: "10.100.0.2", RecordType: "A", TTL: 300},
		{ID: 4, Name: "app.example.com", Value: "10.100.0.3", RecordType: "A", TTL: 300},
		// Not owned by external-dns (no TXT record): must be skipped
		{ID: 5, Name: "other.example.com", Value: "10.100.0.4", RecordType: "A", TTL: 300},
		// Different type for the same name: must be its own endpoint
		{ID: 6, Name: "app.example.com", Value: "lb.example.com", RecordType: "CNAME", TTL: 300},
	}
	mockClient.On("ListDNSRecords", 123, mock.Anything).Return(records, nil)

	p := newTestProvider(mockClient, nil)

	endpoints, err := p.Records(context.Background())
	require.NoError(t, err)

	// One A endpoint with ALL three targets, not three single-target endpoints
	aEndpoints := findEndpoints(endpoints, "app.example.com", "A")
	require.Len(t, aEndpoints, 1)
	assert.ElementsMatch(t, []string{"10.100.0.1", "10.100.0.2", "10.100.0.3"}, []string(aEndpoints[0].Targets))
	assert.Equal(t, endpoint.TTL(300), aEndpoints[0].RecordTTL)
	assert.Equal(t, "test-owner", aEndpoints[0].Labels[endpoint.OwnerLabelKey])

	// TXT ownership record still returned per-name
	txtEndpoints := findEndpoints(endpoints, "app.example.com", "TXT")
	require.Len(t, txtEndpoints, 1)
	assert.Equal(t, endpoint.Targets{testOwnerTXT}, txtEndpoints[0].Targets)

	// CNAME for the same name is a separate endpoint (different type)
	cnameEndpoints := findEndpoints(endpoints, "app.example.com", "CNAME")
	require.Len(t, cnameEndpoints, 1)
	assert.Equal(t, endpoint.Targets{"lb.example.com"}, cnameEndpoints[0].Targets)

	// Unowned record is skipped
	assert.Empty(t, findEndpoints(endpoints, "other.example.com", "A"))

	// Total: A + TXT + CNAME
	assert.Len(t, endpoints, 3)
}

// TestRecordsPagination verifies that all pages of DNS records are fetched,
// not just the first one.
func TestRecordsPagination(t *testing.T) {
	origPageSize := dnsRecordsPageSize
	dnsRecordsPageSize = 2
	defer func() { dnsRecordsPageSize = origPageSize }()

	mockClient := new(MockMyraSecClient)
	mockClient.On("ListDomains", mock.Anything).Return([]myrasec.Domain{{ID: 123, Name: "example.com"}}, nil)

	// Two full pages followed by a short page
	page1 := []myrasec.DNSRecord{
		{ID: 1, Name: "a.example.com", Value: testOwnerTXT, RecordType: "TXT", TTL: 300},
		{ID: 2, Name: "a.example.com", Value: "10.100.0.1", RecordType: "A", TTL: 300},
	}
	page2 := []myrasec.DNSRecord{
		{ID: 3, Name: "b.example.com", Value: testOwnerTXT, RecordType: "TXT", TTL: 300},
		{ID: 4, Name: "b.example.com", Value: "10.100.0.2", RecordType: "A", TTL: 300},
	}
	page3 := []myrasec.DNSRecord{
		{ID: 5, Name: "b.example.com", Value: "10.100.0.3", RecordType: "A", TTL: 300},
	}

	mockClient.On("ListDNSRecords", 123, map[string]string{"page": "1", "pageSize": "2"}).Return(page1, nil).Once()
	mockClient.On("ListDNSRecords", 123, map[string]string{"page": "2", "pageSize": "2"}).Return(page2, nil).Once()
	mockClient.On("ListDNSRecords", 123, map[string]string{"page": "3", "pageSize": "2"}).Return(page3, nil).Once()

	p := newTestProvider(mockClient, nil)

	endpoints, err := p.Records(context.Background())
	require.NoError(t, err)
	mockClient.AssertExpectations(t)

	// Records from every page are visible, including grouping across pages
	aEndpoints := findEndpoints(endpoints, "a.example.com", "A")
	require.Len(t, aEndpoints, 1)
	assert.Equal(t, endpoint.Targets{"10.100.0.1"}, aEndpoints[0].Targets)

	bEndpoints := findEndpoints(endpoints, "b.example.com", "A")
	require.Len(t, bEndpoints, 1)
	assert.ElementsMatch(t, []string{"10.100.0.2", "10.100.0.3"}, []string(bEndpoints[0].Targets))
}

// TestRecordsSingleValueUnchanged verifies the common single-value case still
// produces one endpoint with one target.
func TestRecordsSingleValueUnchanged(t *testing.T) {
	mockClient := new(MockMyraSecClient)

	domains := []myrasec.Domain{{ID: 123, Name: "example.com"}}
	mockClient.On("ListDomains", mock.Anything).Return(domains, nil)

	records := []myrasec.DNSRecord{
		{ID: 1, Name: "www.example.com", Value: testOwnerTXT, RecordType: "TXT", TTL: 300},
		{ID: 2, Name: "www.example.com", Value: "10.100.0.1", RecordType: "A", TTL: 600},
	}
	mockClient.On("ListDNSRecords", 123, mock.Anything).Return(records, nil)

	p := newTestProvider(mockClient, nil)

	endpoints, err := p.Records(context.Background())
	require.NoError(t, err)

	aEndpoints := findEndpoints(endpoints, "www.example.com", "A")
	require.Len(t, aEndpoints, 1)
	assert.Equal(t, endpoint.Targets{"10.100.0.1"}, aEndpoints[0].Targets)
	assert.Equal(t, endpoint.TTL(600), aEndpoints[0].RecordTTL)
}
