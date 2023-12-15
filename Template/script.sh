#!/bin/bash

appResGroup="rg-knock2spot"
appRegion="westeurope"

echo "## Resource Group deployment"
az group create -l $appRegion -n $appResGroup

echo "## Initial App deployment"

# Deploys the app and test NSG
deployResult=$(az deployment group create --resource-group $appResGroup --template-uri https://raw.githubusercontent.com/groovy-sky/knock2spot/master/Template/azuredeploy.json)

echo "## Assigning Contributor role to the App"

appResId=$(echo $deployResult | jq -r '.properties.outputs.containerAppId.value')
nsgId=$(echo $deployResult | jq -r '.properties.outputs.nsgId.value')
appUrl=$(echo $deployResult | jq -r '.properties.outputs.containerAppUrl.value')

# Getting apps managed identity id
identityId=$(az resource show --id $appResId --query "identity.principalId" -o tsv)

# Assigning Contributor role to the NSG
az role assignment create --assignee $identityId --role 'Contributor' --scope $nsgId

echo "## Testing whitelisting - https://$appUrl/whitelistip"

curl https://$appUrl/whitelistip