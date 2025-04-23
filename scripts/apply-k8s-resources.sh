#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Building and deploying Myra Webhook with ExternalDNS...${NC}"

# Build Docker image
echo -e "${YELLOW}Building Docker image...${NC}"
docker build -t myra-webhook:latest .
echo -e "${GREEN}Docker image built successfully.${NC}"

# Load image into kind cluster (if using kind)
echo -e "${YELLOW}Loading Docker image into kind cluster...${NC}"
kind load docker-image myra-webhook:latest
echo -e "${GREEN}Docker image loaded successfully.${NC}"

# Deploy all resources in order
echo -e "${YELLOW}Deploying Kubernetes resources...${NC}"

# 1. Apply Secrets first
echo -e "${YELLOW}Applying Secrets...${NC}"
kubectl apply -f deploy/myra-webhook-secrets.yaml
echo -e "${GREEN}Secrets applied successfully.${NC}"

# 2. Apply Combined Deployment (Myra Webhook + ExternalDNS)
echo -e "${YELLOW}Applying Combined Deployment (Myra Webhook + ExternalDNS)...${NC}"
kubectl apply -f deploy/combined-deployment.yaml
echo -e "${GREEN}Combined Deployment applied successfully.${NC}"

# 2. Apply Nginx Ingress Controller
echo -e "${YELLOW}Nginx Ingress Controller...${NC}"
kubectl apply -f deploy/nginx-ingress-controller.yaml
echo -e "${GREEN}Nginx Ingress Controller applied successfully.${NC}"
# Restart deployments to pick up changes
echo -e "${YELLOW}Restarting deployments...${NC}"

# Restart Combined deployment
echo -e "${YELLOW}Restarting Combined deployment...${NC}"
kubectl rollout restart deployment/myra-externaldns
echo -e "${GREEN}Combined deployment restarted.${NC}"

# Wait for Combined deployment to be ready
echo -e "${YELLOW}Waiting for Combined deployment to be ready...${NC}"
kubectl rollout status deployment/myra-externaldns
echo -e "${GREEN}Combined deployment is ready.${NC}"

if kubectl get deployment ingress-nginx-controller &>/dev/null; then
  echo -e "${YELLOW}Restarting ingress-nginx deployment...${NC}"
  kubectl rollout restart deployment/ingress-nginx-controller
  kubectl rollout status deployment/ingress-nginx-controller
  echo -e "${GREEN}Ingress-nginx deployment restarted.${NC}"
fi

echo -e "${GREEN}All Kubernetes resources have been applied and restarted successfully.${NC}"
echo -e "${YELLOW}The domain filter is set to: dummydomainforkubes.de${NC}"
