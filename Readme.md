# MyraSec External DNS Webhook

A webhook implementation for ExternalDNS that manages DNS records through the MyraSec API. This webhook enables dynamic creation, updating, and deletion of DNS records in MyraSec based on Kubernetes resources (Ingress, Service, etc.).

Built on the official [MyraSec Go Client](https://github.com/Myra-Security-GmbH/myrasec-go), this webhook follows a clean architecture pattern and implements the standard webhook interface for ExternalDNS as specified in the [ExternalDNS Webhook Provider documentation](https://kubernetes-sigs.github.io/external-dns/v0.14.2/tutorials/webhook-provider/).

## Table of Contents

- [MyraSec External DNS Webhook](#myrasec-external-dns-webhook)
  - [Table of Contents](#table-of-contents)
  - [Architecture Overview](#architecture-overview)
  - [Requirements](#requirements)
  - [Installation and Configuration](#installation-and-configuration)
    - [Environment Variables](#environment-variables)
    - [Command Line Arguments](#command-line-arguments)
  - [API Endpoints](#api-endpoints)
  - [Project Structure](#project-structure)
  - [Kubernetes Deployment](#kubernetes-deployment)
    - [ExternalDNS Configuration](#externaldns-configuration)
    - [Combined Deployment](#combined-deployment)
  - [Production Deployment Preparation](#production-deployment-preparation)
  - [Pre-Deployment Checklist](#pre-deployment-checklist)
  - [Development and Testing](#development-and-testing)
    - [Building from Source](#building-from-source)
    - [Building the Docker Image](#building-the-docker-image)
    - [Testing the Webhook](#testing-the-webhook)

## Architecture Overview

The webhook follows a clean, modular architecture with clear separation of concerns:

1. **API Layer** (`pkg/api`): Implements HTTP endpoints that handle requests from ExternalDNS
2. **Provider Layer** (`internal/myrasecprovider`): Core business logic that interacts with MyraSec API
3. **Main Application** (`cmd/webhook`): Entry point that wires everything together

The architecture follows a one-way dependency flow (Main → API → Provider) with no import loops, ensuring maintainability and testability.

The webhook implements these key endpoints:

1. **Domain Filter** (`GET /`): Returns the list of domains the webhook can manage
2. **Records** (`GET /records`): Retrieves the current list of DNS records
3. **Apply Changes** (`POST /records`): Processes DNS record changes (create, update, delete)
4. **Adjust Endpoints** (`POST /adjustendpoints`): Processes and adjusts endpoint configurations

All communication with MyraSec is handled through the official MyraSec Go client, ensuring reliable and consistent API interactions.

## Requirements

- ExternalDNS v0.14.0+ (with webhook provider support)
- Go 1.19+ (for building from source)
- MyraSec account with DNS management permissions
- MyraSec API Key and Secret for authentication
- Domain configured in MyraSec
- Kubernetes cluster (for production deployment)

## Installation and Configuration

### Environment Variables

The webhook is configured using environment variables:

```sh
# Required environment variables
MYRASEC_API_KEY=                  # MyraSec API Key
MYRASEC_API_SECRET=               # MyraSec API Secret
DOMAIN_FILTER=                    # Comma-separated list of domains to manage (e.g., example.com,example.org)

# Optional environment variables
WEBHOOK_LISTEN_ADDRESS=:8080      # Address and port to listen on (default :8080)
WEBHOOK_LISTEN_ADDRESS_PORT=8080  # Alternative way to specify just the port
LOG_LEVEL=info                    # Logging level (debug, info, warn, error)
DRY_RUN=false                     # If true, no actual changes will be made to DNS records
DISABLE_PROTECTION=false          # If true, Myra protection would be disabled for DNS records
TTL=300                           # Default TTL for DNS records (in seconds)
```

### Command Line Arguments

The webhook can also be configured using command line arguments:

```sh
./external-dns-myrasec-webhook \
  --listen-address=:8080 \
  --myrasec-api-key=YOUR_API_KEY \
  --myrasec-api-secret=YOUR_API_SECRET \
  --domain-filter=example.com,example.org \
  --dry-run=false \
  --disable-protection=false \
  --log-level=info \
  --ttl=300
```

## API Endpoints

The webhook implements the following endpoints:

| Endpoint           | Method | Description                       |
| ------------------ | ------ | --------------------------------- |
| `/` or `/webhook`  | GET    | Returns domain filter information |
| `/records`         | GET    | Lists all DNS records             |
| `/records`         | POST   | Applies changes to DNS records    |
| `/adjustendpoints` | POST   | Processes and adjusts endpoints   |
| `/healthz`         | GET    | Health check endpoint             |

## Project Structure

The project follows a standard Go project layout:

```
├── cmd/
│   └── webhook/         # Main application entry point
│       ├── cmd/         # Command line interface
│       └── main.go      # Application entry point
├── deploy/              # Kubernetes deployment manifests
│   ├── combined-deployment.yaml       # Combined webhook and ExternalDNS deployment
│   ├── myra-webhook-secrets.yaml      # Secrets for API credentials
│   ├── nginx-demo.yaml                # Demo application for testing
│   └── nginx-ingress-controller.yaml  # Ingress controller for testing
├── internal/
│   └── myrasecprovider/ # Core provider implementation
│       ├── apply_changes.go           # Implementation of ApplyChanges
│       ├── config.go                  # Provider configuration
│       ├── domain_filter.go          # Domain filtering logic
│       ├── myrasec.go                # Main provider implementation
│       └── records.go                # DNS record management
├── pkg/
│   ├── api/             # HTTP API implementation
│   │   ├── adjust_endpoints_handler.go  # Adjust endpoints handler
│   │   ├── api.go                      # API server implementation
│   │   ├── apply_changes.go            # Apply changes handler
│   │   ├── domain_filter.go            # Domain filter handler
│   │   ├── health.go                   # Health check handler
│   │   ├── records.go                  # Records handler
│   │   └── webhook.go                  # Webhook interface
│   └── errors/          # Custom error types
├── go.mod               # Go module definition
├── go.sum               # Go module checksums
└── Dockerfile           # Container image definition
```

Key components:

- **myrasecprovider**: Implements the ExternalDNS provider interface, handling DNS record management through the MyraSec API
- **api**: Implements the HTTP endpoints required by ExternalDNS webhook specification
- **webhook**: Main application that wires everything together and handles configuration

## Kubernetes Deployment

The webhook can be deployed to Kubernetes using the manifests in the `deploy/` directory.

### ExternalDNS Configuration

To configure ExternalDNS to use this webhook:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: external-dns
spec:
  template:
    spec:
      containers:
        - name: external-dns
          image: k8s.gcr.io/external-dns/external-dns:v0.15.1
          args:
            - --source=service
            - --source=ingress
            - --provider=webhook
            - --webhook-provider-url=http://myra-webhook-service:8080
            - --domain-filter=example.com
            - --policy=upsert-only # sync for allowing deletes and updates, upsert-only for blocking deletes
            - --txt-owner-id=external-dns
            - --registry=txt
```

### Combined Deployment

The project includes a combined deployment manifest (`deploy/combined-deployment.yaml`) that deploys both the webhook and ExternalDNS in a single pod:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myra-externaldns
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: myra-webhook
          image: myra-webhook:latest
          # Configuration omitted for brevity
        - name: external-dns
          image: k8s.gcr.io/external-dns/external-dns:v0.15.1
          # Configuration omitted for brevity
```

This deployment also includes:

- ConfigMap for configuration
- Secrets for API credentials
- ServiceAccount, ClusterRole, and ClusterRoleBinding for RBAC
- Service for exposing the webhook API

## Production Deployment Preparation

Before deploying to production, ensure you replace all placeholder values in the deployment files:

1. In `deploy/myra-webhook-secrets.yaml`:

   - Replace the API key with your actual MyraSec API key
   - Replace the API secret with your actual MyraSec API secret
   - Replace the domain filter with your actual domain

2. In `deploy/combined-deployment.yaml`:

   - Update the `--domain-filter` argument with your actual domain
   - Verify resource limits are appropriate for your environment

3. In `deploy/nginx-ingress-controller.yaml`:
   - Update the hostname annotation with your actual domain

You can use `envsubst` or a similar tool to replace these placeholders:

```sh
export MYRASEC_API_KEY="your-api-key"
export MYRASEC_API_SECRET="your-api-secret"
export DOMAIN_FILTER="your-domain.com"
envsubst < deploy/myra-webhook-secrets.yaml > deploy/myra-webhook-secrets-prod.yaml
```

## Pre-Deployment Checklist

- [ ] Replace all placeholder API credentials in `myra-webhook-secrets.yaml`
- [ ] Update domain filter values in all deployment files
- [ ] Verify resource limits are appropriate for your environment
- [ ] Ensure Kubernetes RBAC permissions are correctly configured
- [ ] Test the webhook in a staging environment before production deployment
- [ ] Verify that the ExternalDNS container can communicate with the webhook
- [ ] Ensure the MyraSec API credentials have the necessary permissions
- [ ] Configure appropriate logging levels for production use

## Development and Testing

The project includes a Dockerfile for building the webhook container image.
Scripts for building and testing the webhook are provided in the `scripts/` directory.
nginx-demo.yaml and nginx-ingress-controller.yaml are provided for testing the webhook.

### Building from Source

```sh
# Clone the repository
git clone https://github.com/netguru/myra-external-dns-webhook.git
cd myra-external-dns-webhook

# Build the application
go build -o external-dns-myrasec-webhook ./cmd/webhook

# Run the application
./external-dns-myrasec-webhook --myrasec-api-key=YOUR_API_KEY --myrasec-api-secret=YOUR_API_SECRET
```

### Building the Docker Image

```sh
docker build -t myra-webhook:latest .
```

### Testing the Webhook

You can test the webhook functionality by sending HTTP requests to the API endpoints:

```sh
# Test the domain filter endpoint
curl http://localhost:8080/

# Test the records endpoint
curl http://localhost:8080/records

# Test creating a DNS record
curl -X POST http://localhost:8080/records -H "Content-Type: application/json" -d '{
  "changes": [
    {
      "action": "CREATE",
      "endpoint": {
        "dnsName": "test.example.com.",
        "recordType": "A",
        "targets": ["192.168.1.1"],
        "recordTTL": 300
      }
    }
  ]
}'
```

For Kubernetes testing, create an Ingress resource with appropriate annotations:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: test-ingress
  annotations:
    external-dns.alpha.kubernetes.io/hostname: test.example.com
spec:
  rules:
    - host: test.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: test-service
                port:
                  number: 80
```

This will trigger ExternalDNS to create a DNS record for `test.example.com` through the webhook.
