appResGroup="delete-me-rg"

appResId=""

identityId=$(az resource show --id $appResId --query "identity.principalId" -o tsv)

az role assignment create --assignee $identityId --role 'Contributor' --scope $appResId