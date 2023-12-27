# knock2spot

![](/logo.svg)

## What is this?

This project is a small website (written on Go), which can be used to seamesly whitelist your IP address on Azure resources. Currenty you can use it to:
1. Reveal your IP address
2. Whitelist your IP address on Azure Paas firewall (currently supports only Storage Account)
3. Whitelist your IP address on Network Security Group for specified destination port

## How to use it?

You don't to compile this project, instead you can use [the Docker image](https://hub.docker.com/repository/docker/gr00vysky/knock2spot) or build it yourself using the [Dockerfile](/Dockerfile).

Easiest way how you can use this project is to deploy it to Azure App Service or Azure Container App. After deployment you'll need to assign managed identity to the app and grant permissions to the managed identity to the resources you want to whitelist your IP address on.

After App is deployed you can use it by navigating to the root of the website. You'll see 3 forms:
1. For NSG whitelisting. Requires NSG resource ID, destination port, rule priority and rule name.
2. For PaaS whitelisting. Requires resource's ID.
3. For IP address revealing.

## How it works?

This project uses [Azure SDK for Go](https://github.com/Azure/azure-sdk-for-go) to interact with Azure in a following way:
1. It tries in different way to get Azure token - from MSI endpoint, environment variables or logged Azure CLI session.

2. It parses requester IP address from request headers and tries to whitelist it on specified resources.

3. Using token and requester's IP address it tries to append IP address to specified NSG rule or PaaS firewall.


## How to run?

Easiest way how you can run this project is to use [the Docker image](https://hub.docker.com/repository/docker/gr00vysky/knock2spot) or build it yourself using the [Dockerfile](/Dockerfile). 

If you need TLS support you can run it on Azure Container App or Azure Web App for Containers. Open [Cloud Shell](https://shell.azure.com) and execute code below:

```
wget https://raw.githubusercontent.com/groovy-sky/knock2spot/master/Template/script.sh
chmod +x script.sh
./script.sh
```

## To-Do

- [ ] Add support for more Azure resources
- [ ] Make default IPs
- [ ] Make force rewrite flag
