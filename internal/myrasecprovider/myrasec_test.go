package myrasecprovider

import (
	"context"
	"testing"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestSelectDomainsMultipleFilters verifies that every domain filter entry is
// considered, not just the first one.
func TestSelectDomainsMultipleFilters(t *testing.T) {
	mockClient := new(MockMyraSecClient)
	domains := []myrasec.Domain{
		{ID: 1, Name: "example.com"},
		{ID: 2, Name: "example.org"},
		{ID: 3, Name: "example.net"},
	}
	mockClient.On("ListDomains", mock.Anything).Return(domains, nil)

	p := newTestProvider(mockClient, []string{"example.com", "example.net"})

	selected, err := p.SelectDomains()
	require.NoError(t, err)
	require.Len(t, selected, 2)
	assert.Equal(t, "example.com", selected[0].Name)
	assert.Equal(t, "example.net", selected[1].Name)
}

// TestSelectDomainsUnmatchedFilterSkipped verifies that a filter entry without
// a matching domain does not silently fall back to an unrelated domain.
func TestSelectDomainsUnmatchedFilterSkipped(t *testing.T) {
	mockClient := new(MockMyraSecClient)
	domains := []myrasec.Domain{
		{ID: 1, Name: "example.com"},
		{ID: 2, Name: "example.org"},
	}
	mockClient.On("ListDomains", mock.Anything).Return(domains, nil)

	p := newTestProvider(mockClient, []string{"example.com", "missing.io"})

	selected, err := p.SelectDomains()
	require.NoError(t, err)
	require.Len(t, selected, 1)
	assert.Equal(t, "example.com", selected[0].Name)
}

// TestSelectDomainsNoMatchReturnsError verifies that filters matching nothing
// produce an error instead of silently managing an arbitrary domain.
func TestSelectDomainsNoMatchReturnsError(t *testing.T) {
	mockClient := new(MockMyraSecClient)
	domains := []myrasec.Domain{
		{ID: 1, Name: "example.com"},
	}
	mockClient.On("ListDomains", mock.Anything).Return(domains, nil)

	p := newTestProvider(mockClient, []string{"missing.io"})

	_, err := p.SelectDomains()
	assert.ErrorIs(t, err, ErrDomainNotFound)
}

// TestSelectDomainsNoFilter verifies the fallback behavior without filters:
// a single domain is used; with multiple domains only the first is managed.
func TestSelectDomainsNoFilter(t *testing.T) {
	t.Run("single domain", func(t *testing.T) {
		mockClient := new(MockMyraSecClient)
		mockClient.On("ListDomains", mock.Anything).Return([]myrasec.Domain{{ID: 1, Name: "example.com"}}, nil)

		p := newTestProvider(mockClient, nil)

		selected, err := p.SelectDomains()
		require.NoError(t, err)
		require.Len(t, selected, 1)
		assert.Equal(t, "example.com", selected[0].Name)
	})

	t.Run("multiple domains uses first", func(t *testing.T) {
		mockClient := new(MockMyraSecClient)
		mockClient.On("ListDomains", mock.Anything).Return([]myrasec.Domain{
			{ID: 1, Name: "example.com"},
			{ID: 2, Name: "example.org"},
		}, nil)

		p := newTestProvider(mockClient, nil)

		selected, err := p.SelectDomains()
		require.NoError(t, err)
		require.Len(t, selected, 1)
		assert.Equal(t, "example.com", selected[0].Name)
	})
}

// TestRecordsMultiDomain verifies that Records() returns endpoints from ALL
// domains matching the filter list, not just the first.
func TestRecordsMultiDomain(t *testing.T) {
	mockClient := new(MockMyraSecClient)
	domains := []myrasec.Domain{
		{ID: 1, Name: "example.com"},
		{ID: 2, Name: "example.org"},
	}
	mockClient.On("ListDomains", mock.Anything).Return(domains, nil)

	mockClient.On("ListDNSRecords", 1, mock.Anything).Return([]myrasec.DNSRecord{
		{ID: 10, Name: "app.example.com", Value: testOwnerTXT, RecordType: "TXT", TTL: 300},
		{ID: 11, Name: "app.example.com", Value: "10.100.0.1", RecordType: "A", TTL: 300},
	}, nil)
	mockClient.On("ListDNSRecords", 2, mock.Anything).Return([]myrasec.DNSRecord{
		{ID: 20, Name: "web.example.org", Value: testOwnerTXT, RecordType: "TXT", TTL: 300},
		{ID: 21, Name: "web.example.org", Value: "10.100.0.2", RecordType: "A", TTL: 300},
	}, nil)

	p := newTestProvider(mockClient, []string{"example.com", "example.org"})

	endpoints, err := p.Records(context.Background())
	require.NoError(t, err)

	require.Len(t, findEndpoints(endpoints, "app.example.com", "A"), 1)
	require.Len(t, findEndpoints(endpoints, "web.example.org", "A"), 1)

	mockClient.AssertCalled(t, "ListDNSRecords", 1, mock.Anything)
	mockClient.AssertCalled(t, "ListDNSRecords", 2, mock.Anything)
}

// TestDomainForEndpoint verifies endpoint-to-domain routing.
func TestDomainForEndpoint(t *testing.T) {
	domains := []myrasec.Domain{
		{ID: 1, Name: "example.com"},
		{ID: 2, Name: "sub.example.com"},
		{ID: 3, Name: "example.org"},
	}

	tests := []struct {
		dnsName   string
		wantID    int
		wantFound bool
	}{
		{"app.example.com", 1, true},
		{"app.sub.example.com", 2, true}, // longest suffix wins
		{"example.org", 3, true},
		{"web.example.org.", 3, true}, // trailing dot tolerated
		{"unrelated.io", 0, false},
	}

	for _, tc := range tests {
		domain, found := domainForEndpoint(domains, tc.dnsName)
		assert.Equal(t, tc.wantFound, found, tc.dnsName)
		if tc.wantFound {
			assert.Equal(t, tc.wantID, domain.ID, tc.dnsName)
		}
	}

	// Single selected domain acts as fallback for non-FQDN names
	single := []myrasec.Domain{{ID: 9, Name: "example.com"}}
	domain, found := domainForEndpoint(single, "shortname")
	assert.True(t, found)
	assert.Equal(t, 9, domain.ID)
}
