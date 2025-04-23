package myrasecprovider

import (
	"sigs.k8s.io/external-dns/endpoint"
)

const (
	CREATE = "CREATE"
	UPDATE = "UPDATE"
	DELETE = "DELETE"
)

// changeTask represents a DNS record change task
type changeTask struct {
	action    string
	change    *endpoint.Endpoint
	oldChange *endpoint.Endpoint // Used for update operations to track the old record state
}
