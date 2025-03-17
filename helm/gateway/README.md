---
title: Gateway Helm Chart
---

This document includes instructions for installing and running Gateway on Kubernetes using Helm Charts.

Helm is an open-source command line tool used for managing Kubernetes applications. It is a graduate project in the CNCF Landscape.

> Note
> 
> The Gateway Helm Chart is provided for deploying Gateway in Kubernetes environments. Please be aware that the code is provided without any warranties. If you encounter any problems, you can report them to our GitHub repository.

## Before you begin

To install Gateway using Helm, ensure you have completed the following:

* Install a Kubernetes server on your machine. For information about installing Kubernetes, refer to [Install Kubernetes](https://kubernetes.io/docs/setup/).
* Install the latest stable version of Helm. For information on installing Helm, refer to [Install Helm](https://helm.sh/docs/intro/install/).

## Install Gateway using Helm

When you install Gateway using Helm, you complete the following tasks:

1. Set up the Gateway Helm repository (optional)
2. Deploy Gateway using Helm
3. Access Gateway

### Set up the Gateway Helm repository (optional)

If the Gateway Helm chart is published to a repository, you can add it to your Helm:

```bash
# Add the Gateway Helm repository
helm repo add gateway-repo oci://ghcr.io/centralmind/gateway-helm/gateway
helm repo update
```

### Deploy Gateway using Helm

When you deploy Gateway Helm charts, we recommend using a separate namespace instead of relying on the default namespace. The default namespace might already have other applications running, which can lead to conflicts and other potential issues.

1. Create a namespace for your Gateway deployment:

```bash
kubectl create namespace gateway-system
```

2. Install Gateway using the Helm chart:

```bash
# Install with default values
helm install gateway ./gateway --namespace gateway-system

# Install with custom values
helm install gateway ./gateway -f values.yaml --namespace gateway-system
```

3. Verify the deployment status:

```bash
helm list -n gateway-system
```

4. Check the overall status of all the objects in the namespace:

```bash
kubectl get all -n gateway-system
```

### Access Gateway

After deploying Gateway, you can access it through the service created by the Helm chart.

1. If you're using `ClusterIP` service type (default), you can port-forward the service to access it locally:

```bash
kubectl port-forward -n gateway-system svc/gateway 8080:8080
```

2. If you've enabled Ingress, you can access Gateway through the hostname specified in your Ingress configuration.

## Customize Gateway configuration

Helm allows you to customize the Gateway deployment by providing a custom `values.yaml` file or by setting values directly on the command line.

### Using a custom values.yaml file

1. Create a custom `values.yaml` file with your desired configuration:

```yaml
image:
  repository: ghcr.io/centralmind/gateway
  tag: "latest"

service:
  type: ClusterIP
  port: 8080

ingress:
  enabled: true
  hosts:
    - host: gateway.example.com
      paths:
        - path: /
          pathType: Prefix

gateway:
  api:
    name: My API
    version: "1.0"
```

2. Install or upgrade Gateway with your custom values:

```bash
# For a new installation
helm install gateway ./gateway -f values.yaml --namespace gateway-system

# For upgrading an existing installation
helm upgrade gateway ./gateway -f values.yaml --namespace gateway-system
```

### Configuration Parameters

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

Gateway can be configured with various options through the `gateway` section in your values.yaml:

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
  --from-literal=API_SECRET_KEY=your-secret-key \
  --namespace gateway-system
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

## Upgrading Gateway

To upgrade your Gateway deployment to a newer version:

```bash
# Update the Helm repository (if using a repository)
helm repo update

# Upgrade Gateway
helm upgrade gateway ./gateway --namespace gateway-system
```

## Uninstalling Gateway

To uninstall/delete the Gateway deployment:

```bash
helm uninstall gateway --namespace gateway-system
```

The command removes all the Kubernetes components associated with the chart and deletes the release.

## Troubleshooting

### Collect logs

To collect logs from the Gateway pod:

```bash
# Get the pod name
kubectl get pods -n gateway-system

# View logs
kubectl logs -n gateway-system <pod-name>

# Follow logs in real-time
kubectl logs -f -n gateway-system <pod-name>
```

### Check pod status

If Gateway is not starting properly, check the pod status:

```bash
kubectl describe pod -n gateway-system <pod-name>
```

### Reset Gateway configuration

If you need to reset Gateway to default configuration:

```bash
helm upgrade gateway ./gateway --reset-values --namespace gateway-system
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
      password: ${DB_PASSWORD}
      database: mydb
      port: 5432
``` 
