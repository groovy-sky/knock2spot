package services

import (
	"fmt"
	"strings"
)

// NetworkACLManager defines operations for services with network restrictions
type NetworkACLManager interface {
	ResourceType() string
	APIVersion() string
	IsAccessRestricted(properties map[string]any) bool
	GetAllowedIPs(properties map[string]any) []string
	BuildPatchBody(currentProperties map[string]any, newIP string) map[string]any
}

// managers maps lowercase resource types to their managers
var managers = map[string]NetworkACLManager{
	"microsoft.storage/storageaccounts": StorageAccountManager{},
	"microsoft.keyvault/vaults":         KeyVaultManager{},
}

// GetManager returns the appropriate NetworkACLManager for a resource type
func GetManager(resourceType string) (NetworkACLManager, error) {
	mgr, ok := managers[strings.ToLower(resourceType)]
	if !ok {
		return nil, fmt.Errorf("unsupported resource type: %s", resourceType)
	}
	return mgr, nil
}

// SupportedResourceTypes returns a list of supported resource types
func SupportedResourceTypes() []string {
	types := make([]string, 0, len(managers))
	for t := range managers {
		types = append(types, t)
	}
	return types
}
