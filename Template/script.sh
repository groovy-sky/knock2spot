#!/bin/bash

appResGroup="knock-group"
appRegion="westeurope"

echo "## Resource Group deployment"
az group create -l $appRegion -n $appResGroup

echo "## Initial App deployment"
deployResult=$(az deployment group create --resource-group $appResGroup --template-uri https://raw.githubusercontent.com/groovy-sky/knock2spot/master/Template/azuredeploy.json)

echo "## Assigning Contributor role to the App"

appResId=$(echo $deployResult | jq -r '.properties.outputs.containerAppId.value')
nsgId=$(echo $deployResult | jq -r '.properties.outputs.nsgId.value')
appUrl=$(echo $deployResult | jq -r '.properties.outputs.containerAppUrl.value')

identityId=$(az resource show --id $appResId --query "identity.principalId" -o tsv)

az role assignment create --assignee $identityId --role 'Contributor' --scope $nsgId

echo "## Testing the App"

curl https://$appUrl/whitelistip