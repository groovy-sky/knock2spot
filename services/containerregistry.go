package services

import (
	"encoding/json"
	"strings"
)

// ContainerRegistryManager handles Azure Container Registry network ACLs
type ContainerRegistryManager struct{}

func (c ContainerRegistryManager) ResourceType() string {
	return "Microsoft.ContainerRegistry/registries"
}

func (c ContainerRegistryManager) APIVersion() string {
	return "2023-07-01"
}

func (c ContainerRegistryManager) IsAccessRestricted(props map[string]any) bool {
	networkRuleSet, ok := props["networkRuleSet"].(map[string]any)
	if !ok {
		return false
	}
	defaultAction, _ := networkRuleSet["defaultAction"].(string)
	return defaultAction == "Deny"
}

func (c ContainerRegistryManager) GetAllowedIPs(props map[string]any) []string {
	var ips []string
	networkRuleSet, ok := props["networkRuleSet"].(map[string]any)
	if !ok {
		return nil
	}

	// Get IP rules
	switch rules := networkRuleSet["ipRules"].(type) {
	case []any:
		for _, r := range rules {
			if m, ok := r.(map[string]any); ok {
				if value, ok := m["value"].(string); ok {
					ips = append(ips, value)
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

	// Fallback to JSON parsing if direct extraction didn't work
	if len(ips) == 0 {
		var parsed struct {
			IPRules []struct {
				Value string `json:"value"`
			} `json:"ipRules"`
		}
		if b, err := json.Marshal(networkRuleSet); err == nil {
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

func (c ContainerRegistryManager) BuildPatchBody(props map[string]any, newIP string) map[string]any {
	// Get existing IP rules
	var ipRules []any
	if networkRuleSet, ok := props["networkRuleSet"].(map[string]any); ok {
		if rules, ok := networkRuleSet["ipRules"].([]any); ok {
			ipRules = make([]any, len(rules))
			copy(ipRules, rules)
		}
	}

	// Append new IP
	ipRules = append(ipRules, map[string]any{
		"value":  newIP,
		"action": "Allow",
	})

	return map[string]any{
		"properties": map[string]any{
			"networkRuleSet": map[string]any{
				"defaultAction": "Deny",
				"bypass":        []string{"AzureServices"},
				"ipRules":       ipRules,
			},
		},
	}
}

func (c ContainerRegistryManager) BuildPatchBodyWithIPs(props map[string]any, allowedIPs []string) map[string]any {
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
			"networkRuleSet": map[string]any{
				"defaultAction": "Deny",
				"bypass":        []string{"AzureServices"},
				"ipRules":       ipRules,
			},
		},
	}
}

func (c ContainerRegistryManager) BuildPatchBodyRemove(props map[string]any, removeIP string) map[string]any {
	removeCandidates := buildRemoveCandidates(removeIP)

	ipRules := make([]any, 0)
	if networkRuleSet, ok := props["networkRuleSet"].(map[string]any); ok {
		if rules, ok := networkRuleSet["ipRules"].([]any); ok {
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
			"networkRuleSet": map[string]any{
				"defaultAction": "Deny",
				"bypass":        []string{"AzureServices"},
				"ipRules":       ipRules,
			},
		},
	}
}
