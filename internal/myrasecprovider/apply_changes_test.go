package myrasecprovider

import (
	"context"
	"errors"
	"testing"

	myrasec "github.com/Myra-Security-GmbH/myrasec-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

// MockMyraSecClient is a mock implementation of the MyraSecAPIClient interface
type MockMyraSecClient struct {
	mock.Mock
}

// ListDomains mocks the ListDomains method
func (m *MockMyraSecClient) ListDomains(params map[string]string) ([]myrasec.Domain, error) {
	args := m.Called(params)
	return args.Get(0).([]myrasec.Domain), args.Error(1)
}

// ListDNSRecords mocks the ListDNSRecords method
func (m *MockMyraSecClient) ListDNSRecords(domainId int, params map[string]string) ([]myrasec.DNSRecord, error) {
	args := m.Called(domainId, params)
	return args.Get(0).([]myrasec.DNSRecord), args.Error(1)
}

// CreateDNSRecord mocks the CreateDNSRecord method
func (m *MockMyraSecClient) CreateDNSRecord(record *myrasec.DNSRecord, domainId int) (*myrasec.DNSRecord, error) {
	args := m.Called(record, domainId)
	return args.Get(0).(*myrasec.DNSRecord), args.Error(1)
}

// UpdateDNSRecord mocks the UpdateDNSRecord method
func (m *MockMyraSecClient) UpdateDNSRecord(record *myrasec.DNSRecord, domainId int) (*myrasec.DNSRecord, error) {
	args := m.Called(record, domainId)
	return args.Get(0).(*myrasec.DNSRecord), args.Error(1)
}

// DeleteDNSRecord mocks the DeleteDNSRecord method
func (m *MockMyraSecClient) DeleteDNSRecord(record *myrasec.DNSRecord, domainId int) (*myrasec.DNSRecord, error) {
	args := m.Called(record, domainId)
	return args.Get(0).(*myrasec.DNSRecord), args.Error(1)
}

// TestApplyChangesBasic tests basic functionality of ApplyChanges
func TestApplyChangesBasic(t *testing.T) {
	// Create a mock client
	mockClient := new(MockMyraSecClient)

	// Create test domains
	domains := []myrasec.Domain{
		{ID: 123, Name: "example.com"},
	}

	// Setup expectations for ListDomains
	mockClient.On("ListDomains", mock.Anything).Return(domains, nil)

	// Setup a test provider with the mock client
	provider := &MyraSecDNSProvider{
		BaseProvider: provider.BaseProvider{},
		apiClient:    mockClient,
		logger:       zap.NewNop(),
		domainName:   "example.com",
		domainId:     "123",
		dryRun:       true, // Use dry run mode to avoid actual API calls
		owner:        "test-owner",
	}

	// Create test changes
	changes := &plan.Changes{
		Create: []*endpoint.Endpoint{
			{
				DNSName:    "test.example.com",
				Targets:    endpoint.Targets{"192.168.1.1"},
				RecordType: "A",
			},
		},
		UpdateOld: []*endpoint.Endpoint{},
		UpdateNew: []*endpoint.Endpoint{},
		Delete:    []*endpoint.Endpoint{},
	}

	// Call the method under test
	err := provider.ApplyChanges(context.Background(), changes)

	// Assert no error occurred
	assert.NoError(t, err)
}

// TestApplyChangesError tests error handling in ApplyChanges
func TestApplyChangesError(t *testing.T) {
	// Create a mock client
	mockClient := new(MockMyraSecClient)

	// Setup expectations for ListDomains to return an error
	mockClient.On("ListDomains", mock.Anything).Return([]myrasec.Domain{}, errors.New("API error"))

	// Setup a test provider with the mock client
	provider := &MyraSecDNSProvider{
		BaseProvider: provider.BaseProvider{},
		apiClient:    mockClient,
		logger:       zap.NewNop(),
		domainName:   "example.com",
		domainId:     "123",
		dryRun:       true,
		owner:        "test-owner",
	}

	// Create test changes
	changes := &plan.Changes{
		Create: []*endpoint.Endpoint{
			{
				DNSName:    "test.example.com",
				Targets:    endpoint.Targets{"192.168.1.1"},
				RecordType: "A",
			},
		},
	}

	// Call the method under test
	err := provider.ApplyChanges(context.Background(), changes)

	// Assert an error occurred
	assert.Error(t, err)

	// Assert that ListDomains was called
	mockClient.AssertCalled(t, "ListDomains", mock.Anything)
}

// TestApplyChangesEmptyChanges tests that empty changes don't cause errors
func TestApplyChangesEmptyChanges(t *testing.T) {
	// Create a mock client
	mockClient := new(MockMyraSecClient)

	// Setup a test provider with the mock client
	provider := &MyraSecDNSProvider{
		BaseProvider: provider.BaseProvider{},
		apiClient:    mockClient,
		logger:       zap.NewNop(),
		domainName:   "example.com",
		domainId:     "123",
		dryRun:       true,
		owner:        "test-owner",
	}

	// Create empty changes
	changes := &plan.Changes{
		Create:    []*endpoint.Endpoint{},
		UpdateOld: []*endpoint.Endpoint{},
		UpdateNew: []*endpoint.Endpoint{},
		Delete:    []*endpoint.Endpoint{},
	}

	// Call the method under test
	err := provider.ApplyChanges(context.Background(), changes)

	// Assert no error occurred
	assert.NoError(t, err)
}

// TestApplyChangesUnequalUpdateSlices tests that unequal update slices cause an error
func TestApplyChangesUnequalUpdateSlices(t *testing.T) {
	// Create a mock client
	mockClient := new(MockMyraSecClient)

	// Setup a test provider with the mock client
	provider := &MyraSecDNSProvider{
		BaseProvider: provider.BaseProvider{},
		apiClient:    mockClient,
		logger:       zap.NewNop(),
		domainName:   "example.com",
		domainId:     "123",
		dryRun:       true,
		owner:        "test-owner",
	}

	// Create changes with unequal update slices
	changes := &plan.Changes{
		UpdateOld: []*endpoint.Endpoint{
			{
				DNSName:    "update1.example.com",
				Targets:    endpoint.Targets{"192.168.1.1"},
				RecordType: "A",
			},
			{
				DNSName:    "update2.example.com",
				Targets:    endpoint.Targets{"192.168.1.2"},
				RecordType: "A",
			},
		},
		UpdateNew: []*endpoint.Endpoint{
			{
				DNSName:    "update1.example.com",
				Targets:    endpoint.Targets{"192.168.1.3"},
				RecordType: "A",
			},
		},
	}

	// Call the method under test
	err := provider.ApplyChanges(context.Background(), changes)

	// Assert an error occurred
	assert.Error(t, err)
}
