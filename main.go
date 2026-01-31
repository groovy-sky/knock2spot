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
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := EnsureIPAllowed(ctx, cred, resourceID, ip, mgr); err != nil {
			log.Printf("failed to allow IP: %v", err)
			http.Error(w, "failed to allow IP", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	http.HandleFunc("/close", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ip, err := getRequesterIP(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := EnsureIPRemoved(ctx, cred, resourceID, ip, mgr); err != nil {
			log.Printf("failed to remove IP: %v", err)
			http.Error(w, "failed to remove IP", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
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
