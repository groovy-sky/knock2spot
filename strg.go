package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources/v3"
)

var APIVersions = map[string]string{
	"Microsoft.Storage/storageAccounts": "2023-01-01",
}

type ResourceValue struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Location   string                 `json:"location"`
	Properties map[string]interface{} `json:"properties"`
	Tags       map[string]string      `json:"tags"`
}

func ParseResourceValues(jsonData []byte) ([]ResourceValue, error) {
	var values []ResourceValue
	if err := json.Unmarshal(jsonData, &values); err != nil {
		return nil, fmt.Errorf("failed to parse resource values: %w", err)
	}
	return values, nil
}

func CallResource(ctx context.Context, cred azcore.TokenCredential, resourceID, method, apiVersion string, body io.Reader) (int, map[string]any, error) {
	method = strings.ToUpper(method)
	subID, err := parseSubscriptionID(resourceID)
	if err != nil {
		return 0, nil, err
	}

	if method == http.MethodGet {
		client, err := armresources.NewClient(subID, cred, nil)
		if err != nil {
			return 0, nil, fmt.Errorf("client error: %w", err)
		}
		resp, err := client.GetByID(ctx, resourceID, apiVersion, nil)
		if err != nil {
			return 0, nil, fmt.Errorf("get error: %w", err)
		}
		status := http.StatusOK
		raw, _ := json.Marshal(resp.GenericResource)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		return status, out, nil
	}

	// other verbs: sign manually
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})
	if err != nil {
		return 0, nil, fmt.Errorf("token error: %w", err)
	}

	url := fmt.Sprintf("https://management.azure.com%s?api-version=%s", resourceID, apiVersion)
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return 0, nil, fmt.Errorf("request build error: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "arm-generic-call/1.0")

	client := &http.Client{Timeout: 60 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("http error: %w", err)
	}
	defer res.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if len(b) == 0 {
		return res.StatusCode, nil, nil
	}
	var parsed map[string]any
	if err := json.Unmarshal(b, &parsed); err != nil {
		return res.StatusCode, nil, fmt.Errorf("json parse error: %w; body: %s", err, string(b))
	}
	if res.StatusCode >= 400 {
		return res.StatusCode, parsed, fmt.Errorf("ARM error %d: %s", res.StatusCode, string(b))
	}
	return res.StatusCode, parsed, nil
}

func parseSubscriptionID(resourceID string) (string, error) {
	const prefix = "/subscriptions/"
	i := strings.Index(strings.ToLower(resourceID), prefix)
	if i == -1 {
		return "", fmt.Errorf("resourceID missing %s", prefix)
	}
	start := i + len(prefix)
	j := strings.Index(resourceID[start:], "/")
	if j == -1 {
		return "", fmt.Errorf("resourceID missing segment after subscription")
	}
	return resourceID[start : start+j], nil
}

func main() {
	ctx := context.Background()
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("credential error: %v", err)
	}

	resourceID := os.Getenv("STORAGE_RESOURCE_ID")
	if strings.TrimSpace(resourceID) == "" {
		log.Fatal("missing env var: RESOURCE_ID")
	}

	apiVersion := APIVersions["Microsoft.Storage/storageAccounts"]
	status, body, err := CallResource(ctx, cred, resourceID, http.MethodGet, apiVersion, nil)
	if err != nil {
		log.Fatalf("call failed: %v", err)
	}
	fmt.Printf("Status: %d\nBody: %+v\n", status, body)
}
