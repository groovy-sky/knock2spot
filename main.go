package main

import (
	"context"
	"log"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/groovy-sky/knock2spot/services"
)

func main() {
	ctx := context.Background()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("credential error: %v", err)
	}

	resourceID := os.Getenv("RESOURCE_ID")
	if strings.TrimSpace(resourceID) == "" {
		log.Fatal("missing env var: RESOURCE_ID")
	}

	publicIP := os.Getenv("PUBLIC_IP")
	if strings.TrimSpace(publicIP) == "" {
		log.Fatal("missing env var: PUBLIC_IP")
	}

	// Auto-detect resource type from resource ID
	resourceType, err := ParseResourceType(resourceID)
	if err != nil {
		log.Fatalf("failed to parse resource type: %v", err)
	}

	// Get the appropriate manager for this resource type
	mgr, err := services.GetManager(resourceType)
	if err != nil {
		log.Fatalf("unsupported resource type %s: %v\nSupported types: %v", resourceType, err, services.SupportedResourceTypes())
	}

	// Ensure IP is allowed
	if err := EnsureIPAllowed(ctx, cred, resourceID, publicIP, mgr); err != nil {
		log.Fatalf("failed to ensure IP allowed: %v", err)
	}
}
