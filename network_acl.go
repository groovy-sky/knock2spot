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

	if rawAcls, ok := props["networkAcls"]; ok {
		if b, err := json.Marshal(rawAcls); err == nil {
			fmt.Printf("Raw networkAcls: %s\n", string(b))
		}
	} else if b, err := json.Marshal(props); err == nil {
		fmt.Printf("Properties snapshot: %s\n", string(b))
	}

	if rawAcls, ok := props["networkAcls"]; ok {
		if b, err := json.Marshal(rawAcls); err == nil {
			fmt.Printf("Raw networkAcls: %s\n", string(b))
		}
	} else if b, err := json.Marshal(props); err == nil {
		fmt.Printf("Properties snapshot: %s\n", string(b))
	}

	// 2. Check if restricted
	if !mgr.IsAccessRestricted(props) {
		fmt.Println("Resource is not configured for selected networks, skipping IP addition")
		return nil
	}

	// 3. Check if IP already exists
	allowedIPs := mgr.GetAllowedIPs(props)
	newBase := normalizeIPBase(newIP)
	for _, ip := range allowedIPs {
		if normalizeIPBase(ip) == newBase {
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

// EnsureIPRemoved removes an IP if present in the allowed list
func EnsureIPRemoved(ctx context.Context, cred azcore.TokenCredential, resourceID, removeIP string, mgr services.NetworkACLManager) error {
	status, body, err := CallResource(ctx, cred, resourceID, http.MethodGet, mgr.APIVersion(), nil)
	if err != nil {
		return fmt.Errorf("GET failed: %w", err)
	}
	fmt.Printf("GET Status: %d\n", status)

	props, ok := body["properties"].(map[string]any)
	if !ok {
		return fmt.Errorf("invalid response: missing properties")
	}

	allowedIPs := mgr.GetAllowedIPs(props)
	fmt.Printf("Allowed IPs: %+v\n", allowedIPs)
	removeBase := normalizeIPBase(removeIP)
	remaining := make([]string, 0, len(allowedIPs))
	removed := false
	for _, ip := range allowedIPs {
		trimmed := strings.TrimSpace(ip)
		if normalizeIPBase(trimmed) == removeBase {
			removed = true
			continue
		}
		remaining = append(remaining, trimmed)
	}
	if !removed {
		fmt.Printf("IP %s not found in the allowed list\n", removeIP)
		return nil
	}

	fmt.Printf("Removing IP %s from allowed list\n", removeIP)
	patchBody := mgr.BuildPatchBodyWithIPs(props, remaining)
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

func normalizeIPBase(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "/") {
		parts := strings.SplitN(trimmed, "/", 2)
		return strings.TrimSpace(parts[0])
	}
	return trimmed
}
