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

type ActionResult struct {
	Changed bool
	Reason  string
}

func (r ActionResult) String() string {
	if r.Changed {
		return "changed"
	}
	if r.Reason == "" {
		return "unchanged"
	}
	return "unchanged - " + r.Reason
}

// EnsureIPAllowed checks if access is restricted and adds the IP if not already present
func EnsureIPAllowed(ctx context.Context, cred azcore.TokenCredential, resourceID, newIP string, mgr services.NetworkACLManager) (ActionResult, error) {
	// 1. GET current state
	status, body, err := CallResource(ctx, cred, resourceID, http.MethodGet, mgr.APIVersion(), nil)
	if err != nil {
		return ActionResult{}, fmt.Errorf("GET failed: %w", err)
	}
	logf("GET Status: %d", status)

	props, ok := body["properties"].(map[string]any)
	if !ok {
		return ActionResult{}, fmt.Errorf("invalid response: missing properties")
	}

	if rawAcls, ok := props["networkAcls"]; ok {
		if b, err := json.Marshal(rawAcls); err == nil {
			logf("Raw networkAcls: %s", string(b))
		}
	} else if b, err := json.Marshal(props); err == nil {
		logf("Properties snapshot: %s", string(b))
	}

	// 2. Check if restricted
	if !mgr.IsAccessRestricted(props) {
		logf("Resource is not configured for selected networks, skipping IP addition")
		return ActionResult{Changed: false, Reason: "ip restriction not enabled"}, nil
	}

	// 3. Check if IP already exists
	allowedIPs := mgr.GetAllowedIPs(props)
	newBase := normalizeIPBase(newIP)
	for _, ip := range allowedIPs {
		if normalizeIPBase(ip) == newBase {
			logf("IP %s already exists in the allowed list", newIP)
			return ActionResult{Changed: false, Reason: "ip already in list"}, nil
		}
	}

	// 4. PATCH with new IP
	logf("Adding IP %s to allowed list", newIP)
	patchBody := mgr.BuildPatchBody(props, newIP)
	data, err := json.Marshal(patchBody)
	if err != nil {
		return ActionResult{}, fmt.Errorf("failed to marshal PATCH body: %w", err)
	}

	patchStatus, patchResp, err := CallResource(ctx, cred, resourceID, http.MethodPatch, mgr.APIVersion(), strings.NewReader(string(data)))
	if err != nil {
		return ActionResult{}, fmt.Errorf("PATCH failed: %w", err)
	}
	logf("PATCH Status: %d\nResponse: %+v", patchStatus, patchResp)

	return ActionResult{Changed: true}, nil
}

// EnsureIPRemoved removes an IP if present in the allowed list
func EnsureIPRemoved(ctx context.Context, cred azcore.TokenCredential, resourceID, removeIP string, mgr services.NetworkACLManager) (ActionResult, error) {
	status, body, err := CallResource(ctx, cred, resourceID, http.MethodGet, mgr.APIVersion(), nil)
	if err != nil {
		return ActionResult{}, fmt.Errorf("GET failed: %w", err)
	}
	logf("GET Status: %d", status)

	props, ok := body["properties"].(map[string]any)
	if !ok {
		return ActionResult{}, fmt.Errorf("invalid response: missing properties")
	}

	if rawAcls, ok := props["networkAcls"]; ok {
		if b, err := json.Marshal(rawAcls); err == nil {
			logf("Raw networkAcls: %s", string(b))
		}
	} else if b, err := json.Marshal(props); err == nil {
		logf("Properties snapshot: %s", string(b))
	}

	if !mgr.IsAccessRestricted(props) {
		logf("Resource is not configured for selected networks, skipping IP removal")
		return ActionResult{Changed: false, Reason: "ip restriction not enabled"}, nil
	}

	allowedIPs := mgr.GetAllowedIPs(props)
	logf("Allowed IPs: %+v", allowedIPs)
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
		logf("IP %s not found in the allowed list", removeIP)
		return ActionResult{Changed: false, Reason: "ip not in list"}, nil
	}

	logf("Removing IP %s from allowed list", removeIP)
	patchBody := mgr.BuildPatchBodyWithIPs(props, remaining)
	data, err := json.Marshal(patchBody)
	if err != nil {
		return ActionResult{}, fmt.Errorf("failed to marshal PATCH body: %w", err)
	}

	patchStatus, patchResp, err := CallResource(ctx, cred, resourceID, http.MethodPatch, mgr.APIVersion(), strings.NewReader(string(data)))
	if err != nil {
		return ActionResult{}, fmt.Errorf("PATCH failed: %w", err)
	}
	logf("PATCH Status: %d\nResponse: %+v", patchStatus, patchResp)

	return ActionResult{Changed: true}, nil
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
