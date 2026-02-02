package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/groovy-sky/knock2spot/services"
)

var verbose = strings.TrimSpace(os.Getenv("VERBOSE")) != ""

func main() {
	ctx := context.Background()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("credential error: %v", err)
	}

	authToken := strings.TrimSpace(os.Getenv("AUTH_TOKEN"))
	if authToken != "" {
		log.Printf("Authentication enabled")
	} else {
		log.Printf("WARNING: Authentication disabled - AUTH_TOKEN not set")
	}

	resourceIDs := parseResourceIDs(os.Getenv("RESOURCE_IDS"))
	if len(resourceIDs) == 0 {
		log.Fatal("missing env var: RESOURCE_IDS")
	}

	managers := make(map[string]services.NetworkACLManager, len(resourceIDs))
	for _, resourceID := range resourceIDs {
		resourceType, err := ParseResourceType(resourceID)
		if err != nil {
			log.Fatalf("failed to parse resource type for %s: %v", resourceID, err)
		}
		mgr, err := services.GetManager(resourceType)
		if err != nil {
			log.Fatalf("unsupported resource type %s: %v\nSupported types: %v", resourceType, err, services.SupportedResourceTypes())
		}
		managers[resourceID] = mgr
	}

	port := strings.TrimSpace(os.Getenv("HTTP_PORT"))
	if port == "" {
		port = "8080"
	}
	if _, err := strconv.Atoi(port); err != nil {
		log.Fatalf("invalid HTTP_PORT value: %v", err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "knock2spot service\nEndpoints: /open, /close\nQuery params: ?provider=<storage|keyvault|containerregistry>\n")
	})

	http.HandleFunc("/open", func(w http.ResponseWriter, r *http.Request) {
		if authToken != "" && !authenticate(r, authToken) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ip, err := getRequesterIP(r)
		if err != nil {
			log.Printf("invalid requester IP: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		log.Printf("requester_ip=%s", ip)

		// Filter resources by provider if specified
		targetResources, err := filterResourcesByProvider(r, resourceIDs, managers)
		if err != nil {
			log.Printf("provider filter error: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		processed := 0
		failed := 0
		for _, resourceID := range targetResources {
			mgr := managers[resourceID]
			result, err := EnsureIPAllowed(ctx, cred, resourceID, ip, mgr)
			if err != nil {
				log.Printf("failed to allow IP for %s: %v", resourceID, err)
				failed++
				continue
			}
			log.Printf("resource=%s result=%s", resourceID, result.String())
			processed++
		}

		if failed > 0 {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	})

	http.HandleFunc("/close", func(w http.ResponseWriter, r *http.Request) {
		if authToken != "" && !authenticate(r, authToken) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ip, err := getRequesterIP(r)
		if err != nil {
			log.Printf("invalid requester IP: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		log.Printf("requester_ip=%s", ip)

		// Filter resources by provider if specified
		targetResources, err := filterResourcesByProvider(r, resourceIDs, managers)
		if err != nil {
			log.Printf("provider filter error: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		processed := 0
		failed := 0
		for _, resourceID := range targetResources {
			mgr := managers[resourceID]
			result, err := EnsureIPRemoved(ctx, cred, resourceID, ip, mgr)
			if err != nil {
				log.Printf("failed to remove IP for %s: %v", resourceID, err)
				failed++
				continue
			}
			log.Printf("resource=%s result=%s", resourceID, result.String())
			processed++
		}

		if failed > 0 {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	})

	addr := ":" + port
	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func getRequesterIP(r *http.Request) (string, error) {
	if ip := strings.TrimSpace(r.Header.Get("x-envoy-external-address")); ip != "" {
		if parsed, err := parseIPValue(ip); err == nil {
			return parsed, nil
		}
	}
	if ip := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); ip != "" {
		if parsed, err := parseIPValue(ip); err == nil {
			return parsed, nil
		}
	}
	if ip := strings.TrimSpace(os.Getenv("PUBLIC_IP")); ip != "" {
		return parseIPValue(ip)
	}
	return "", errMissingIPHeader
}

var errMissingIPHeader = &ipHeaderError{msg: "missing x-envoy-external-address or X-Forwarded-For header"}

type ipHeaderError struct {
	msg string
}

func (e *ipHeaderError) Error() string {
	return e.msg
}

func parseIPValue(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", errMissingIPHeader
	}
	if strings.Contains(value, ",") {
		parts := strings.Split(value, ",")
		value = strings.TrimSpace(parts[0])
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return "", &ipHeaderError{msg: "invalid IP address"}
	}
	return ip.String(), nil
}

func parseResourceIDs(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	parts := strings.Split(trimmed, ",")
	ids := make([]string, 0, len(parts))
	for _, part := range parts {
		id := strings.TrimSpace(part)
		if id == "" {
			continue
		}
		ids = append(ids, id)
	}
	return ids
}

func logf(format string, args ...any) {
	if !verbose {
		return
	}
	log.Printf(format, args...)
}

// filterResourcesByProvider filters resources based on the provider query parameter
// Extracts provider name from resource type (e.g., "Microsoft.ContainerRegistry/registries" -> "ContainerRegistry")
func filterResourcesByProvider(r *http.Request, resourceIDs []string, managers map[string]services.NetworkACLManager) ([]string, error) {
	providerFilter := strings.TrimSpace(r.URL.Query().Get("provider"))
	if providerFilter == "" {
		return resourceIDs, nil
	}

	providerFilter = strings.ToLower(providerFilter)
	filtered := make([]string, 0)

	for _, resourceID := range resourceIDs {
		mgr := managers[resourceID]
		resourceType := mgr.ResourceType()

		// Extract provider name from "Microsoft.ContainerRegistry/registries" -> "ContainerRegistry"
		providerName := extractProviderName(resourceType)
		if strings.ToLower(providerName) == providerFilter {
			filtered = append(filtered, resourceID)
		}
	}

	if len(filtered) == 0 {
		return nil, fmt.Errorf("no resources found for provider: %s", providerFilter)
	}

	return filtered, nil
}

// extractProviderName extracts the provider name from a resource type
// e.g., "Microsoft.ContainerRegistry/registries" -> "ContainerRegistry"
func extractProviderName(resourceType string) string {
	parts := strings.Split(resourceType, "/")
	if len(parts) < 1 {
		return ""
	}

	// Get the first part (e.g., "Microsoft.ContainerRegistry")
	firstPart := parts[0]

	// Split by dot and get the last segment
	dotParts := strings.Split(firstPart, ".")
	if len(dotParts) >= 2 {
		return dotParts[len(dotParts)-1]
	}

	return firstPart
}

// authenticate validates the token from Authorization header
func authenticate(r *http.Request, requiredToken string) bool {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return false
	}

	token := strings.TrimSpace(authHeader)
	return token == requiredToken
}
