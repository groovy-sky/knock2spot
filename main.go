package main

import (
	"context"
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

	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8080"
	}
	if _, err := strconv.Atoi(port); err != nil {
		log.Fatalf("invalid PORT value: %v", err)
	}

	http.HandleFunc("/open", func(w http.ResponseWriter, r *http.Request) {
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
		for _, resourceID := range resourceIDs {
			mgr := managers[resourceID]
			result, err := EnsureIPAllowed(ctx, cred, resourceID, ip, mgr)
			if err != nil {
				log.Printf("failed to allow IP for %s: %v", resourceID, err)
				continue
			}
			log.Printf("resource=%s result=%s", resourceID, result.String())
		}
		w.WriteHeader(http.StatusNoContent)
	})

	http.HandleFunc("/close", func(w http.ResponseWriter, r *http.Request) {
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
		for _, resourceID := range resourceIDs {
			mgr := managers[resourceID]
			result, err := EnsureIPRemoved(ctx, cred, resourceID, ip, mgr)
			if err != nil {
				log.Printf("failed to remove IP for %s: %v", resourceID, err)
				continue
			}
			log.Printf("resource=%s result=%s", resourceID, result.String())
		}
		w.WriteHeader(http.StatusNoContent)
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
