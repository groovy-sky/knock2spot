package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

const (
	targetIDsEnv = "TARGET_RESOURCE_IDS"
	debugIPEnv   = "DEBUG_IP"
	debugCIDREnv = "DEBUG_IP_CIDR"

	maxAttempts   = 4
	baseBackoff   = 300 * time.Millisecond
	perResourceTO = 15 * time.Second
)

type result struct {
	ResourceID string `json:"resourceId"`
	Status     string `json:"status"`
	Message    string `json:"message,omitempty"`
}

type response struct {
	IP      string   `json:"ip"`
	Status  string   `json:"status"`
	Results []result `json:"results,omitempty"`
}

func main() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("auth init failed: %v", err)
	}

	armClient := NewARMClient(cred)
	resourceIDs := loadTargets()

	mux := http.NewServeMux()
	mux.HandleFunc("/open", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ip, ipCIDR, err := resolveIP(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, response{Status: "error", IP: ip, Results: []result{{Status: "error", Message: err.Error()}}})
			return
		}

		ctx := r.Context()
		resultsCh := make(chan result, len(resourceIDs))
		for _, rid := range resourceIDs {
			rid := rid
			go func() {
				ctxTO, cancel := context.WithTimeout(ctx, perResourceTO)
				defer cancel()
				resultsCh <- processResource(ctxTO, armClient, ipCIDR, rid)
			}()
		}

		var results []result
		allOK := true
		for range resourceIDs {
			res := <-resultsCh
			results = append(results, res)
			if res.Status != "ok" {
				allOK = false
			}
		}

		if allOK {
			writeJSON(w, http.StatusOK, response{IP: ip, Status: "ok"})
		} else {
			writeJSON(w, http.StatusInternalServerError, response{IP: ip, Status: "error", Results: results})
		}
	})

	addr := ":8080"
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func loadTargets() []string {
	val := strings.TrimSpace(os.Getenv(targetIDsEnv))
	if val == "" {
		log.Fatal("TARGET_RESOURCE_IDS is required")
	}
	var ids []string
	for _, t := range strings.Split(val, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		ids = append(ids, t)
	}
	return ids
}

func resolveIP(r *http.Request) (string, string, error) {
	if v := strings.TrimSpace(os.Getenv(debugCIDREnv)); v != "" {
		ip, cidr, err := parseIPOrCIDR(v)
		return ip, cidr, err
	}
	if v := strings.TrimSpace(os.Getenv(debugIPEnv)); v != "" {
		ip, cidr, err := parseIPOrCIDR(v)
		return ip, cidr, err
	}
	if v := strings.TrimSpace(r.URL.Query().Get("ip")); v != "" {
		ip, cidr, err := parseIPOrCIDR(v)
		return ip, cidr, err
	}
	return extractIP(r)
}

func extractIP(r *http.Request) (string, string, error) {
	var ipStr string
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		ipStr = strings.TrimSpace(parts[0])
	} else {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		ipStr = host
	}
	if ipStr == "" {
		return "", "", errors.New("unable to determine caller IP")
	}
	if net.ParseIP(ipStr) == nil || strings.Contains(ipStr, ":") {
		return "", "", fmt.Errorf("invalid or unsupported IP: %s", ipStr)
	}
	return ipStr, ipStr + "/32", nil
}

func parseIPOrCIDR(v string) (string, string, error) {
	if strings.Contains(v, "/") {
		ip, _, err := net.ParseCIDR(v)
		if err != nil || ip == nil || strings.Contains(ip.String(), ":") {
			return "", "", fmt.Errorf("invalid or unsupported CIDR: %s", v)
		}
		return ip.String(), v, nil
	}
	if net.ParseIP(v) == nil || strings.Contains(v, ":") {
		return "", "", fmt.Errorf("invalid or unsupported IP: %s", v)
	}
	return v, v + "/32", nil
}

func processResource(ctx context.Context, arm *ARMClient, ipCIDR, resourceID string) result {
	err := withRetry(ctx, func(ctx context.Context) error {
		return WhitelistByResourceID(ctx, arm, resourceID, ipCIDR)
	})
	if err != nil {
		return result{ResourceID: resourceID, Status: "error", Message: err.Error()}
	}
	return result{ResourceID: resourceID, Status: "ok"}
}

func withRetry(ctx context.Context, f func(ctx context.Context) error) error {
	var attempt int
	for {
		err := f(ctx)
		if err == nil {
			return nil
		}
		attempt++
		if attempt >= maxAttempts {
			return err
		}
		select {
		case <-time.After(time.Duration(attempt) * time.Duration(attempt) * baseBackoff):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, resp response) {
	writeJSON(w, code, resp)
}

type ARMClient struct {
	cred azcore.TokenCredential
	http *http.Client
}

func NewARMClient(cred azcore.TokenCredential) *ARMClient {
	return &ARMClient{
		cred: cred,
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *ARMClient) authHeader(ctx context.Context) (string, error) {
	tok, err := c.cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})
	if err != nil {
		return "", fmt.Errorf("get token: %w", err)
	}
	return "Bearer " + tok.Token, nil
}

func (c *ARMClient) do(ctx context.Context, method, url string, payload any) error {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal payload: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	auth, err := c.authHeader(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s %s failed: %s (%s)", method, url, resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

func (c *ARMClient) get(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	auth, err := c.authHeader(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GET failed: %s (%s)", resp.Status, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

var ErrNotFound = errors.New("not found")

// ---------- Resource ID parsing ----------

type ResourceID struct {
	Subscription  string
	ResourceGroup string
	Provider      string
	TypeSegments  []string
}

func parseResourceID(id string) (ResourceID, error) {
	trim := strings.Trim(id, "/")
	parts := strings.Split(trim, "/")
	if len(parts) < 8 || !strings.EqualFold(parts[0], "subscriptions") || !strings.EqualFold(parts[2], "resourceGroups") || !strings.EqualFold(parts[4], "providers") {
		return ResourceID{}, errors.New("invalid resource ID")
	}
	return ResourceID{
		Subscription:  parts[1],
		ResourceGroup: parts[3],
		Provider:      strings.ToLower(parts[5]),
		TypeSegments:  parts[6:],
	}, nil
}

// ---------- Dispatcher ----------

func WhitelistByResourceID(ctx context.Context, arm *ARMClient, resourceID, ipCIDR string) error {
	r, err := parseResourceID(resourceID)
	if err != nil {
		return err
	}
	switch r.Provider {
	case "microsoft.web":
		return handleWeb(ctx, arm, r, ipCIDR)
	case "microsoft.sql":
		return handleSQL(ctx, arm, r, ipCIDR)
	case "microsoft.storage":
		return handleStorage(ctx, arm, r, ipCIDR)
	case "microsoft.documentdb":
		return handleCosmos(ctx, arm, r, ipCIDR)
	case "microsoft.keyvault":
		return handleKeyVault(ctx, arm, r, ipCIDR)
	case "microsoft.eventhub":
		return handleEventHub(ctx, arm, r, ipCIDR)
	case "microsoft.servicebus":
		return handleServiceBus(ctx, arm, r, ipCIDR)
	case "microsoft.eventgrid":
		return handleEventGrid(ctx, arm, r, ipCIDR)
	case "microsoft.containerregistry":
		return handleACR(ctx, arm, r, ipCIDR)
	default:
		return fmt.Errorf("unsupported provider: %s", r.Provider)
	}
}

// ---------- Handlers (merge-aware) ----------

func handleWeb(ctx context.Context, arm *ARMClient, r ResourceID, ip string) error {
	if len(r.TypeSegments) < 2 || r.TypeSegments[0] != "sites" {
		return errors.New("unexpected Microsoft.Web type")
	}
	site := r.TypeSegments[1]
	slotPart := ""
	if len(r.TypeSegments) >= 4 && r.TypeSegments[2] == "slots" {
		slotPart = "/slots/" + r.TypeSegments[3]
	}
	url := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Web/sites/%s%s/config/ipSecurityRestrictions/default?api-version=2023-12-01",
		r.Subscription, r.ResourceGroup, site, slotPart,
	)

	var current struct {
		Properties struct {
			IpSecurityRestrictions []struct {
				Name      string `json:"name"`
				IPAddress string `json:"ipAddress"`
				Action    string `json:"action"`
				Priority  int    `json:"priority"`
				Tag       string `json:"tag"`
			} `json:"ipSecurityRestrictions"`
		} `json:"properties"`
	}
	if err := arm.get(ctx, url, &current); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}

	for _, r := range current.Properties.IpSecurityRestrictions {
		if r.IPAddress == ip && strings.EqualFold(r.Action, "allow") {
			return nil
		}
	}

	priority := 300
	existingPriorities := map[int]bool{}
	for _, r := range current.Properties.IpSecurityRestrictions {
		existingPriorities[r.Priority] = true
	}
	for existingPriorities[priority] {
		priority++
	}

	current.Properties.IpSecurityRestrictions = append(current.Properties.IpSecurityRestrictions, struct {
		Name      string `json:"name"`
		IPAddress string `json:"ipAddress"`
		Action    string `json:"action"`
		Priority  int    `json:"priority"`
		Tag       string `json:"tag"`
	}{
		Name: "allow-ip", IPAddress: ip, Action: "Allow", Priority: priority, Tag: "Default",
	})

	payload := map[string]any{
		"properties": map[string]any{
			"ipSecurityRestrictions": current.Properties.IpSecurityRestrictions,
		},
	}
	return arm.do(ctx, http.MethodPut, url, payload)
}

func handleSQL(ctx context.Context, arm *ARMClient, r ResourceID, ipCIDR string) error {
	if len(r.TypeSegments) < 2 {
		return errors.New("unexpected Microsoft.Sql type")
	}
	ruleName := "allow-ip"
	ip := strings.SplitN(ipCIDR, "/", 2)[0]

	switch strings.ToLower(r.TypeSegments[0]) {
	case "servers":
		server := r.TypeSegments[1]
		url := fmt.Sprintf(
			"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Sql/servers/%s/firewallRules/%s?api-version=2023-08-01-preview",
			r.Subscription, r.ResourceGroup, server, ruleName,
		)
		var current struct {
			Properties struct {
				StartIP string `json:"startIpAddress"`
				EndIP   string `json:"endIpAddress"`
			} `json:"properties"`
		}
		if err := arm.get(ctx, url, &current); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if current.Properties.StartIP == ip && current.Properties.EndIP == ip {
			return nil
		}
		payload := map[string]any{
			"properties": map[string]any{
				"startIpAddress": ip,
				"endIpAddress":   ip,
			},
		}
		return arm.do(ctx, http.MethodPut, url, payload)

	case "managedinstances", "managedInstances":
		mi := r.TypeSegments[1]
		url := fmt.Sprintf(
			"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Sql/managedInstances/%s/firewallRules/%s?api-version=2023-08-01-preview",
			r.Subscription, r.ResourceGroup, mi, ruleName,
		)
		var current struct {
			Properties struct {
				StartIP string `json:"startIpAddress"`
				EndIP   string `json:"endIpAddress"`
			} `json:"properties"`
		}
		if err := arm.get(ctx, url, &current); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if current.Properties.StartIP == ip && current.Properties.EndIP == ip {
			return nil
		}
		payload := map[string]any{
			"properties": map[string]any{
				"startIpAddress": ip,
				"endIpAddress":   ip,
			},
		}
		return arm.do(ctx, http.MethodPut, url, payload)
	default:
		return errors.New("unsupported Microsoft.Sql child type")
	}
}

func handleStorage(ctx context.Context, arm *ARMClient, r ResourceID, ip string) error {
	if len(r.TypeSegments) < 2 || r.TypeSegments[0] != "storageAccounts" {
		return errors.New("unexpected Microsoft.Storage type")
	}
	account := r.TypeSegments[1]
	url := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s?api-version=2023-05-01",
		r.Subscription, r.ResourceGroup, account,
	)

	var current struct {
		Properties struct {
			NetworkAcls struct {
				DefaultAction string `json:"defaultAction"`
				Bypass        string `json:"bypass"`
				IpRules       []struct {
					Action string `json:"action"`
					Value  string `json:"value"`
				} `json:"ipRules"`
			} `json:"networkAcls"`
		} `json:"properties"`
	}
	if err := arm.get(ctx, url, &current); err != nil {
		return err
	}

	for _, r := range current.Properties.NetworkAcls.IpRules {
		if r.Value == ip && strings.EqualFold(r.Action, "allow") {
			return nil
		}
	}

	current.Properties.NetworkAcls.IpRules = append(current.Properties.NetworkAcls.IpRules, struct {
		Action string `json:"action"`
		Value  string `json:"value"`
	}{Action: "Allow", Value: ip})

	payload := map[string]any{
		"properties": map[string]any{
			"networkAcls": map[string]any{
				"defaultAction": current.Properties.NetworkAcls.DefaultAction,
				"bypass":        current.Properties.NetworkAcls.Bypass,
				"ipRules":       current.Properties.NetworkAcls.IpRules,
			},
		},
	}
	return arm.do(ctx, http.MethodPatch, url, payload)
}

func handleCosmos(ctx context.Context, arm *ARMClient, r ResourceID, ip string) error {
	if len(r.TypeSegments) < 2 || r.TypeSegments[0] != "databaseAccounts" {
		return errors.New("unexpected Microsoft.DocumentDB type")
	}
	account := r.TypeSegments[1]
	url := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.DocumentDB/databaseAccounts/%s?api-version=2023-09-15",
		r.Subscription, r.ResourceGroup, account,
	)

	var current struct {
		Properties struct {
			IpRules []struct {
				IP string `json:"ipAddressOrRange"`
			} `json:"ipRules"`
		} `json:"properties"`
	}
	if err := arm.get(ctx, url, &current); err != nil {
		return err
	}

	for _, r := range current.Properties.IpRules {
		if r.IP == ip {
			return nil
		}
	}

	current.Properties.IpRules = append(current.Properties.IpRules, struct {
		IP string `json:"ipAddressOrRange"`
	}{IP: ip})

	payload := map[string]any{
		"properties": map[string]any{
			"ipRules": current.Properties.IpRules,
		},
	}
	return arm.do(ctx, http.MethodPatch, url, payload)
}

func handleKeyVault(ctx context.Context, arm *ARMClient, r ResourceID, ip string) error {
	if len(r.TypeSegments) < 2 || r.TypeSegments[0] != "vaults" {
		return errors.New("unexpected Microsoft.KeyVault type")
	}
	vault := r.TypeSegments[1]
	url := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.KeyVault/vaults/%s?api-version=2023-07-01",
		r.Subscription, r.ResourceGroup, vault,
	)

	var current struct {
		Properties struct {
			NetworkAcls struct {
				DefaultAction string `json:"defaultAction"`
				Bypass        string `json:"bypass"`
				IpRules       []struct {
					Value string `json:"value"`
				} `json:"ipRules"`
			} `json:"networkAcls"`
		} `json:"properties"`
	}
	if err := arm.get(ctx, url, &current); err != nil {
		return err
	}

	for _, r := range current.Properties.NetworkAcls.IpRules {
		if r.Value == ip {
			return nil
		}
	}

	current.Properties.NetworkAcls.IpRules = append(current.Properties.NetworkAcls.IpRules, struct {
		Value string `json:"value"`
	}{Value: ip})

	payload := map[string]any{
		"properties": map[string]any{
			"networkAcls": map[string]any{
				"defaultAction": current.Properties.NetworkAcls.DefaultAction,
				"bypass":        current.Properties.NetworkAcls.Bypass,
				"ipRules":       current.Properties.NetworkAcls.IpRules,
			},
		},
	}
	return arm.do(ctx, http.MethodPatch, url, payload)
}

func handleEventHub(ctx context.Context, arm *ARMClient, r ResourceID, ip string) error {
	if len(r.TypeSegments) < 2 || r.TypeSegments[0] != "namespaces" {
		return errors.New("unexpected Microsoft.EventHub type")
	}
	ns := r.TypeSegments[1]
	url := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.EventHub/namespaces/%s/NetworkRuleSets/default?api-version=2024-01-01",
		r.Subscription, r.ResourceGroup, ns,
	)

	var current struct {
		Properties struct {
			DefaultAction string `json:"defaultAction"`
			IpRules       []struct {
				IPMask string `json:"ipMask"`
				Action string `json:"action"`
			} `json:"ipRules"`
		} `json:"properties"`
	}
	if err := arm.get(ctx, url, &current); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}

	for _, r := range current.Properties.IpRules {
		if r.IPMask == ip && strings.EqualFold(r.Action, "allow") {
			return nil
		}
	}

	current.Properties.IpRules = append(current.Properties.IpRules, struct {
		IPMask string `json:"ipMask"`
		Action string `json:"action"`
	}{IPMask: ip, Action: "Allow"})

	if current.Properties.DefaultAction == "" {
		current.Properties.DefaultAction = "Deny"
	}

	payload := map[string]any{
		"properties": map[string]any{
			"defaultAction": current.Properties.DefaultAction,
			"ipRules":       current.Properties.IpRules,
		},
	}
	return arm.do(ctx, http.MethodPut, url, payload)
}

func handleServiceBus(ctx context.Context, arm *ARMClient, r ResourceID, ip string) error {
	if len(r.TypeSegments) < 2 || r.TypeSegments[0] != "namespaces" {
		return errors.New("unexpected Microsoft.ServiceBus type")
	}
	ns := r.TypeSegments[1]
	url := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ServiceBus/namespaces/%s/networkRuleSets/default?api-version=2021-11-01",
		r.Subscription, r.ResourceGroup, ns,
	)

	var current struct {
		Properties struct {
			DefaultAction string `json:"defaultAction"`
			IpRules       []struct {
				IPMask string `json:"ipMask"`
				Action string `json:"action"`
			} `json:"ipRules"`
		} `json:"properties"`
	}
	if err := arm.get(ctx, url, &current); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}

	for _, r := range current.Properties.IpRules {
		if r.IPMask == ip && strings.EqualFold(r.Action, "allow") {
			return nil
		}
	}

	current.Properties.IpRules = append(current.Properties.IpRules, struct {
		IPMask string `json:"ipMask"`
		Action string `json:"action"`
	}{IPMask: ip, Action: "Allow"})

	if current.Properties.DefaultAction == "" {
		current.Properties.DefaultAction = "Deny"
	}

	payload := map[string]any{
		"properties": map[string]any{
			"defaultAction": current.Properties.DefaultAction,
			"ipRules":       current.Properties.IpRules,
		},
	}
	return arm.do(ctx, http.MethodPut, url, payload)
}

func handleEventGrid(ctx context.Context, arm *ARMClient, r ResourceID, ip string) error {
	if len(r.TypeSegments) < 2 || r.TypeSegments[0] != "domains" {
		return errors.New("unexpected Microsoft.EventGrid type")
	}
	domain := r.TypeSegments[1]
	url := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.EventGrid/domains/%s?api-version=2022-06-15",
		r.Subscription, r.ResourceGroup, domain,
	)

	var current struct {
		Properties struct {
			InboundIpRules []struct {
				IPMask string `json:"ipMask"`
				Action string `json:"action"`
			} `json:"inboundIpRules"`
		} `json:"properties"`
	}
	if err := arm.get(ctx, url, &current); err != nil {
		return err
	}

	for _, r := range current.Properties.InboundIpRules {
		if r.IPMask == ip && strings.EqualFold(r.Action, "allow") {
			return nil
		}
	}

	current.Properties.InboundIpRules = append(current.Properties.InboundIpRules, struct {
		IPMask string `json:"ipMask"`
		Action string `json:"action"`
	}{IPMask: ip, Action: "Allow"})

	payload := map[string]any{
		"properties": map[string]any{
			"inboundIpRules": current.Properties.InboundIpRules,
		},
	}
	return arm.do(ctx, http.MethodPatch, url, payload)
}

func handleACR(ctx context.Context, arm *ARMClient, r ResourceID, ip string) error {
	if len(r.TypeSegments) < 2 || r.TypeSegments[0] != "registries" {
		return errors.New("unexpected Microsoft.ContainerRegistry type")
	}
	registry := r.TypeSegments[1]
	url := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerRegistry/registries/%s?api-version=2023-01-01-preview",
		r.Subscription, r.ResourceGroup, registry,
	)

	var current struct {
		Properties struct {
			NetworkRuleSet struct {
				DefaultAction string `json:"defaultAction"`
				IpRules       []struct {
					Action string `json:"action"`
					Value  string `json:"value"`
				} `json:"ipRules"`
			} `json:"networkRuleSet"`
		} `json:"properties"`
	}
	if err := arm.get(ctx, url, &current); err != nil {
		return err
	}

	for _, r := range current.Properties.NetworkRuleSet.IpRules {
		if r.Value == ip && strings.EqualFold(r.Action, "allow") {
			return nil
		}
	}

	current.Properties.NetworkRuleSet.IpRules = append(current.Properties.NetworkRuleSet.IpRules, struct {
		Action string `json:"action"`
		Value  string `json:"value"`
	}{Action: "Allow", Value: ip})

	if current.Properties.NetworkRuleSet.DefaultAction == "" {
		current.Properties.NetworkRuleSet.DefaultAction = "Deny"
	}

	payload := map[string]any{
		"properties": map[string]any{
			"networkRuleSet": map[string]any{
				"defaultAction": current.Properties.NetworkRuleSet.DefaultAction,
				"ipRules":       current.Properties.NetworkRuleSet.IpRules,
			},
		},
	}
	return arm.do(ctx, http.MethodPatch, url, payload)
}
