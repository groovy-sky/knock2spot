package services

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
	rules, ok := acls["ipRules"].([]any)
	if !ok {
		return nil
	}
	var ips []string
	for _, r := range rules {
		if m, ok := r.(map[string]any); ok {
			if ip, ok := m["value"].(string); ok {
				ips = append(ips, ip)
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
