package myrasecprovider

import (
	"github.com/netguru/myra-external-dns-webhook/pkg/errors"
)

var (
	// ErrMissingAPIKey is returned when MyraSec API key is not provided
	ErrMissingAPIKey = errors.ErrMissingAPIKey

	// ErrMissingZone is returned when MyraSec zone is not provided
	ErrMissingZone = errors.ErrMissingZone

	// ErrMissingAPISecret is returned when MyraSec API secret is not provided
	ErrMissingAPISecret = errors.ErrMissingAPISecret

	// ErrDomainNotFound is returned when the specified domain is not found
	ErrDomainNotFound = errors.ErrDomainNotFound

	// ErrAPIRequestFailed is returned when a request to the MyraSec API fails
	ErrAPIRequestFailed = errors.ErrAPIRequestFailed

	// ErrInvalidJSONFormat is returned when the JSON payload cannot be parsed
	ErrInvalidJSONFormat = errors.ErrInvalidJSONFormat
)
