package services

import (
	"encoding/json"
	"strings"
)

// StorageAccountManager handles Azure Storage Accounts network ACLs
type StorageAccountManager struct{}

func (s StorageAccountManager) ResourceType() string {
	return "Microsoft.Storage/storageAccounts"
}

func (s StorageAccountManager) APIVersion() string {
	return "2023-01-01"
}

func (s StorageAccountManager) IsAccessRestricted(props map[string]any) bool {
	acls, ok := props["networkAcls"].(map[string]any)
	if !ok {
		return false
	}
	defaultAction, _ := acls["defaultAction"].(string)
	return defaultAction == "Deny"
}

func (s StorageAccountManager) GetAllowedIPs(props map[string]any) []string {
	acls, ok := props["networkAcls"].(map[string]any)
	if !ok {
		return nil
	}
	var ips []string
	switch rules := acls["ipRules"].(type) {
	case []any:
		for _, r := range rules {
			if m, ok := r.(map[string]any); ok {
				if ip, ok := m["value"].(string); ok {
					ips = append(ips, ip)
				}
			}
		}
	case []map[string]any:
		for _, m := range rules {
			if ip, ok := m["value"].(string); ok {
				ips = append(ips, ip)
			}
		}
	case []map[string]string:
		for _, m := range rules {
			if ip, ok := m["value"]; ok {
				ips = append(ips, ip)
			}
		}
	}
	if len(ips) == 0 {
		var parsed struct {
			IPRules []struct {
				Value string `json:"value"`
			} `json:"ipRules"`
		}
		if b, err := json.Marshal(acls); err == nil {
			if err := json.Unmarshal(b, &parsed); err == nil {
				for _, r := range parsed.IPRules {
					if strings.TrimSpace(r.Value) != "" {
						ips = append(ips, r.Value)
					}
				}
			}
		}
	}
	return ips
}

func (s StorageAccountManager) BuildPatchBody(props map[string]any, newIP string) map[string]any {
	// Get existing IP rules
	var ipRules []any
	if acls, ok := props["networkAcls"].(map[string]any); ok {
		if rules, ok := acls["ipRules"].([]any); ok {
			ipRules = rules
		}
	}

	// Append new IP
	ipRules = append(ipRules, map[string]any{
		"value":  newIP,
		"action": "Allow",
	})

	return map[string]any{
		"properties": map[string]any{
			"networkAcls": map[string]any{
				"defaultAction": "Deny",
				"ipRules":       ipRules,
			},
		},
	}
}

func (s StorageAccountManager) BuildPatchBodyWithIPs(props map[string]any, allowedIPs []string) map[string]any {
	ipRules := make([]any, 0, len(allowedIPs))
	for _, ip := range allowedIPs {
		trimmed := strings.TrimSpace(ip)
		if trimmed == "" {
			continue
		}
		ipRules = append(ipRules, map[string]any{
			"value":  trimmed,
			"action": "Allow",
		})
	}

	return map[string]any{
		"properties": map[string]any{
			"networkAcls": map[string]any{
				"defaultAction": "Deny",
				"ipRules":       ipRules,
			},
		},
	}
}

func (s StorageAccountManager) BuildPatchBodyRemove(props map[string]any, removeIP string) map[string]any {
	removeCandidates := buildRemoveCandidates(removeIP)

	ipRules := make([]any, 0)
	if acls, ok := props["networkAcls"].(map[string]any); ok {
		if rules, ok := acls["ipRules"].([]any); ok {
			for _, r := range rules {
				if m, ok := r.(map[string]any); ok {
					if ip, ok := m["value"].(string); ok {
						trimmed := strings.TrimSpace(ip)
						if _, found := removeCandidates[trimmed]; found {
							continue
						}
					}
				}
				ipRules = append(ipRules, r)
			}
		}
	}

	return map[string]any{
		"properties": map[string]any{
			"networkAcls": map[string]any{
				"defaultAction": "Deny",
				"ipRules":       ipRules,
			},
		},
	}
}
