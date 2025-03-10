---
title: Gateway Helm Chart
---

A simple Helm chart for deploying Gateway in Kubernetes.

## Installation

```bash
# Install with default values
helm install gateway ./gateway

# Install with custom values
helm install gateway ./gateway -f values.yaml
```

## Configuration Parameters

| Parameter | Description             | Default Value |
|-----------|-------------------------|---------------|
| `image.repository` | Docker image name       | `ghcr.io/centralmind/gateway` |
| `image.tag` | Docker image tag        | `latest` |
| `imagePullSecrets` | List of image pull secrets | `[]` |
| `service.type` | Kubernetes service type | `ClusterIP` |
| `service.port` | Service port            | `8080` |
| `ingress.enabled` | Enable Ingress          | `true` |
| `ingress.kind` | Ingress type (IngressRoute) | `IngressRoute` |
| `ingress.entryPoints` | Traefik entry points | `["web"]` |
| `ingress.hosts[0].host` | Ingress hostname        | `demo-gw.centralmind.io` |
| `ingress.hosts[0].paths[0].path` | Ingress path            | `/` |
| `resources.limits.cpu` | CPU limit               | `500m` |
| `resources.limits.memory` | Memory limit            | `512Mi` |
| `resources.requests.cpu` | CPU request             | `100m` |
| `resources.requests.memory` | Memory request          | `128Mi` |

### Gateway Configuration

```yaml
gateway:
  api:
    name: Awesome API      # API Name
    version: "1.0"        # API Version
  database:
    type: postgres        # Database type
    connection: ''        # Database connection string
```

## Managing Secrets

Gateway supports environment variables expansion in the configuration using `${VARIABLE_NAME}` syntax. In Kubernetes environment, you can manage these secrets using:

### Using Kubernetes Secrets

1. Create a Kubernetes secret:
```bash
kubectl create secret generic gateway-secrets \
  --from-literal=DB_PASSWORD=mysecret \
  --from-literal=API_SECRET_KEY=your-secret-key
```

2. Reference secrets in your values.yaml:
```yaml
gateway:
  envFrom:
    - secretRef:
        name: gateway-secrets
  api:
    auth:
      secret_key: ${API_SECRET_KEY}
  database:
    connection:
      password: ${DB_PASSWORD}
```

### Using External Secret Managers

For production environments, you can use external secret managers like HashiCorp Vault or AWS Secrets Manager with tools like External Secrets Operator:

```yaml
gateway:
  envFrom:
    - secretRef:
        name: gateway-external-secrets
```

## Example values.yaml

```yaml
image:
  repository: ghcr.io/centralmind/gateway
  tag: "0.0.0-rc0"

# Optional: configure image pull secrets if using private registry
imagePullSecrets:
  - name: registry-secret

ingress:
  enabled: true
  kind: IngressRoute
  entryPoints:
    - web
  hosts:
    - host: my-gateway.example.com
      paths:
        - path: /
          pathType: Prefix

gateway:
  api:
    name: My API
    version: "2.0"
  database:
    type: postgres
    connection: |
      hosts:
        - postgres.database
      user: myuser
      password: mypassword
      database: mydb
      port: 5432
``` 
