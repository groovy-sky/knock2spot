# knock2spot

![](/logo.svg)

A lightweight Go web service that automatically whitelists your IP address on Azure PaaS firewalls.

## What does it do?

When you're working remotely or from changing locations, constantly updating firewall rules for Azure resources is tedious. This service:
- Detects your public IP address from incoming requests
- Adds it to Azure resource firewall allow lists
- Removes it when you're done

**Supported Azure Resources:**
- Storage Accounts
- Key Vaults
- Container Registries

## How it works

1. **You make a request** to `/open` endpoint
2. **Service detects your IP** from request headers (`X-Forwarded-For` or `x-envoy-external-address`)
3. **Checks the firewall** on configured Azure resources using Azure SDK
4. **Adds your IP** to the allowed list if not already present
5. **Returns 204** on success

When done, call `/close` to remove your IP from the firewall rules.

## Quick Start

### 1. Deploy to Azure

Deploy to Azure Container App or App Service using the [Docker image](https://hub.docker.com/repository/docker/gr00vysky/knock2spot):

```bash
# Using Azure Container Apps
az containerapp create \
  --name knock2spot \
  --resource-group myResourceGroup \
  --image gr00vysky/knock2spot:latest \
  --target-port 8080 \
  --ingress external \
  --env-vars \
    RESOURCE_IDS="/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.Storage/storageAccounts/myaccount" \
    AUTH_TOKEN="your-secret-token-here"
```

### 2. Enable Managed Identity

```bash
# Enable system-assigned managed identity
az containerapp identity assign --name knock2spot --resource-group myResourceGroup

# Grant permissions to manage network ACLs on target resources
az role assignment create \
  --assignee <managed-identity-principal-id> \
  --role "Contributor" \
  --scope "/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.Storage/storageAccounts/myaccount"
```

### 3. Use the service

```bash
# Whitelist your IP
curl -H "Authorization: your-secret-token-here" \
  https://knock2spot.myapp.io/open

# Remove your IP
curl -H "Authorization: your-secret-token-here" \
  https://knock2spot.myapp.io/close
```

## Configuration

**Environment Variables:**

| Variable | Required | Description | Default |
|----------|----------|-------------|---------|
| `RESOURCE_IDS` | Yes | Comma-separated Azure resource IDs to manage | - |
| `AUTH_TOKEN` | No | Secret token for endpoint authentication | None (⚠️ unprotected) |
| `HTTP_PORT` | No | HTTP listen port | 8080 |
| `VERBOSE` | No | Enable detailed logging | false |
| `PUBLIC_IP` | No | Fallback IP if headers unavailable | - |

**Example with multiple resources:**
```bash
RESOURCE_IDS="/subscriptions/xxx/.../storageAccounts/storage1,/subscriptions/xxx/.../vaults/keyvault1"
```

## API Endpoints

### `GET /`
Returns service information

### `POST /open`
Adds your IP to firewall allow lists

**Optional query parameters:**
- `?provider=storage` - Only affect Storage Accounts
- `?provider=keyvault` - Only affect Key Vaults
- `?provider=containerregistry` - Only affect Container Registries

**Authentication:** Required if `AUTH_TOKEN` is set

**Headers:**
```
Authorization: YOUR_SECRET_TOKEN
```

**Response:**
- `204 No Content` - Success
- `401 Unauthorized` - Invalid/missing token
- `400 Bad Request` - Invalid IP or provider
- `500 Internal Server Error` - Azure API error

### `POST /close`
Removes your IP from firewall allow lists

Same parameters and responses as `/open`.

## Security Notes

⚠️ **Always set `AUTH_TOKEN` in production** - without it, anyone can modify your firewall rules

The service:
- Uses Azure Managed Identity for Azure API authentication
- Never stores or logs the `AUTH_TOKEN`
- Only modifies network ACLs on explicitly configured resources
- Logs all operations with timestamps and requester IPs

## Local Development

```bash
# Build
go build -o knock2spot

# Run locally
export RESOURCE_IDS="/subscriptions/.../resourceGroups/.../providers/Microsoft.Storage/storageAccounts/test"
export AUTH_TOKEN="dev-token"
export VERBOSE="true"

# Authenticate with Azure CLI for local testing
az login

# Start service
./knock2spot
```

## Troubleshooting

**"missing x-envoy-external-address or X-Forwarded-For header"**
- Set `PUBLIC_IP` environment variable with your IP address
- Ensure your reverse proxy/load balancer passes `X-Forwarded-For`

**"credential error"**
- Enable managed identity on your Azure deployment
- Or use `az login` for local development

**"unsupported resource type"**
- Verify resource ID format matches Azure conventions
- Currently supports: Storage/Container Registry/Key Vault only
