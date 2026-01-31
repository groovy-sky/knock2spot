package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/groovy-sky/knock2spot/services"
)

// EnsureIPAllowed checks if access is restricted and adds the IP if not already present
func EnsureIPAllowed(ctx context.Context, cred azcore.TokenCredential, resourceID, newIP string, mgr services.NetworkACLManager) error {
	// 1. GET current state
	status, body, err := CallResource(ctx, cred, resourceID, http.MethodGet, mgr.APIVersion(), nil)
	if err != nil {
		return fmt.Errorf("GET failed: %w", err)
	}
	fmt.Printf("GET Status: %d\n", status)

	props, ok := body["properties"].(map[string]any)
	if !ok {
		return fmt.Errorf("invalid response: missing properties")
	}

	// 2. Check if restricted
	if !mgr.IsAccessRestricted(props) {
		fmt.Println("Resource is not configured for selected networks, skipping IP addition")
		return nil
	}

	// 3. Check if IP already exists
	allowedIPs := mgr.GetAllowedIPs(props)
	for _, ip := range allowedIPs {
		if ip == newIP {
			fmt.Printf("IP %s already exists in the allowed list\n", newIP)
			return nil
		}
	}

	// 4. PATCH with new IP
	fmt.Printf("Adding IP %s to allowed list\n", newIP)
	patchBody := mgr.BuildPatchBody(props, newIP)
	data, err := json.Marshal(patchBody)
	if err != nil {
		return fmt.Errorf("failed to marshal PATCH body: %w", err)
	}

	patchStatus, patchResp, err := CallResource(ctx, cred, resourceID, http.MethodPatch, mgr.APIVersion(), strings.NewReader(string(data)))
	if err != nil {
		return fmt.Errorf("PATCH failed: %w", err)
	}
	fmt.Printf("PATCH Status: %d\nResponse: %+v\n", patchStatus, patchResp)

	return nil
}
