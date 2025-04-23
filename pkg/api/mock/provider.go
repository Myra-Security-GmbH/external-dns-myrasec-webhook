package mock

import (
	"context"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

// MockProvider is a mock implementation of the provider.Provider interface for testing
type MockProvider struct {
	RecordsFn      func(ctx context.Context) ([]*endpoint.Endpoint, error)
	ApplyChangesFn func(ctx context.Context, changes *plan.Changes) error
}

// Records calls the RecordsFn or returns an empty slice if not set
func (m *MockProvider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	if m.RecordsFn != nil {
		return m.RecordsFn(ctx)
	}
	return []*endpoint.Endpoint{}, nil
}

// ApplyChanges calls the ApplyChangesFn or returns nil if not set
func (m *MockProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	if m.ApplyChangesFn != nil {
		return m.ApplyChangesFn(ctx, changes)
	}
	return nil
}
