//go:build storageexample
// +build storageexample

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage/v3"
)

// Generated from example definition:
// https://github.com/Azure/azure-rest-api-specs/blob/4e9df3afd38a1cfa00a5d49419dce51bd014601f/specification/storage/resource-manager/Microsoft.Storage/stable/2025-06-01/examples/StorageAccountUpdateDisablePublicNetworkAccess.json
func main() {
	resourceID := mustEnv("STORAGE_RESOURCE_ID")
	subscriptionID, resourceGroup, accountName, err := parseStorageResourceID(resourceID)
	if err != nil {
		log.Fatalf("invalid STORAGE_RESOURCE_ID: %v", err)
	}
	allowIP := strings.TrimSpace(os.Getenv("ALLOW_IP_CIDR"))
	if allowIP == "" {
		log.Fatalf("missing ALLOW_IP_CIDR")
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	clientFactory, err := armstorage.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	client := clientFactory.NewAccountsClient()
	current, err := client.GetProperties(ctx, resourceGroup, accountName, nil)
	if err != nil {
		log.Fatalf("failed to get storage account properties: %v", err)
	}
	if current.Properties == nil || current.Properties.NetworkRuleSet == nil || current.Properties.NetworkRuleSet.DefaultAction == nil {
		log.Fatalf("network rules are not configured; refusing to modify access")
	}
	if *current.Properties.NetworkRuleSet.DefaultAction != armstorage.DefaultActionDeny {
		log.Fatalf("storage account is not restricted (DefaultAction=%s); refusing to modify access", *current.Properties.NetworkRuleSet.DefaultAction)
	}

	networkRuleSet := current.Properties.NetworkRuleSet
	for _, rule := range networkRuleSet.IPRules {
		if rule != nil && rule.IPAddressOrRange != nil && strings.EqualFold(strings.TrimSpace(*rule.IPAddressOrRange), allowIP) {
			log.Println("ip already allowed")
			return
		}
	}
	networkRuleSet.IPRules = append(networkRuleSet.IPRules, &armstorage.IPRule{
		Action:           to.Ptr("Allow"),
		IPAddressOrRange: to.Ptr(allowIP),
	})

	_, err = client.Update(ctx, resourceGroup, accountName, armstorage.AccountUpdateParameters{
		Properties: &armstorage.AccountPropertiesUpdateParameters{
			NetworkRuleSet: networkRuleSet,
		},
	}, nil)
	if err != nil {
		log.Fatalf("failed to finish the request: %v", err)
	}
	log.Println("storage account updated")
}

func parseStorageResourceID(id string) (string, string, string, error) {
	trim := strings.Trim(id, "/")
	parts := strings.Split(trim, "/")
	if len(parts) < 8 || !strings.EqualFold(parts[0], "subscriptions") || !strings.EqualFold(parts[2], "resourceGroups") || !strings.EqualFold(parts[4], "providers") {
		return "", "", "", fmt.Errorf("invalid resource ID")
	}
	if !strings.EqualFold(parts[5], "Microsoft.Storage") || !strings.EqualFold(parts[6], "storageAccounts") {
		return "", "", "", fmt.Errorf("resource ID is not a storage account")
	}
	return parts[1], parts[3], parts[7], nil
}

func mustEnv(key string) string {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		log.Fatalf("missing %s", key)
	}
	return val
}
