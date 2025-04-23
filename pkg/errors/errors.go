package errors

import "errors"

var (
	// ErrMissingAPIKey is returned when MyraSec API key is not provided
	ErrMissingAPIKey = errors.New("myrasec API key is required")

	// ErrMissingZone is returned when MyraSec zone is not provided
	ErrMissingZone = errors.New("myrasec zone is required")

	// ErrMissingAPISecret is returned when MyraSec API secret is not provided
	ErrMissingAPISecret = errors.New("myrasec API secret is required")

	// ErrDomainNotFound is returned when the specified domain is not found
	ErrDomainNotFound = errors.New("domain not found")

	// ErrAPIRequestFailed is returned when a request to the MyraSec API fails
	ErrAPIRequestFailed = errors.New("API request to MyraSec failed")

	// ErrInvalidJSONFormat is returned when the JSON payload cannot be parsed
	ErrInvalidJSONFormat = errors.New("invalid JSON format in request")
)
