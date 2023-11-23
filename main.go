package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
)

// Checks that input matches Azure Resource Id format
func validateResId(input string) bool {
	// Validates that input is valid Azure Resource Id using regex
	regex := `^\/subscriptions\/.{36}\/resourceGroups\/.*\/providers\/[a-zA-Z0-9]*.[a-zA-Z0-9]*\/[a-zA-Z0-9]*\/.*`
	r := regexp.MustCompile(regex)
	return r.MatchString(input)
}

// Gets Azure Resource's names of subscription, group, resource type etc.
func parseResourceId(resourceId string) (subscriptionId, resourceGroup, resourceProvider, resourceName string) {
	// takes Azure resource Id and parses sub id, group, resource type and name
	parts := strings.Split(resourceId, "/")
	subscriptionId = parts[2]
	resourceGroup = parts[4]
	resourceProvider = strings.Join(parts[6:8], "/")
	resourceName = parts[8]
	return subscriptionId, resourceGroup, resourceProvider, resourceName
}

// Returns form to input NSG Id, destination port, rule number and rule name
func defaultHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`<!DOCTYPE html>
	<html>
	<head>
	  <meta charset="UTF-8" />
	</head>
	<body>
	<div>
	<form action="whitelistip" method="POST">
		<label for="nsgid">NSG's ID:</label><input type="text" id="nsgid" name="nsgid" value="" required /> <br><br>
		
		<label for="dstport">Destination's Port:</label><input type="text" id="dstport" value="" name="dstport" required /><br><br>
	
		<label for="rulenumber">Security Rule Number:</label><input type="text" id="rulenumber" name="rulenumber" value="" required><br><br>
	
		<label for="rulename">Security Rule Name:</label><input type="text" id="rulename" name="rulename" value="" required><br><br>
		
		<input type="submit" value="Submit">
	</form>
	</div>
	</body>
	</html>`))
}

// Returns client's IP address
func myIpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Forwarded-For") != "" {
		w.Write([]byte(strings.Split(r.Header.Get("X-Forwarded-For"), ":")[0]))
	} else if r.Header.Get("Host") != "" {
		w.Write([]byte(strings.Split(r.Header.Get("Host"), ":")[0]))
	} else if r.RemoteAddr != "" {
		w.Write([]byte(strings.Split(r.RemoteAddr, ":")[0]))
	}
}

// Takes incoming IP address and adds it to NSG
func whitelistipHandler(w http.ResponseWriter, r *http.Request, cred *azidentity.ChainedTokenCredential) {
	var ip, nsgId, dstPort, ruleName, ruleNumberStr string
	var networkClientFactory *armnetwork.ClientFactory

	// Get the request body and parse input data generated from default.html in case of POST request
	switch r.Method {
	case "POST":
		if err := r.ParseForm(); err != nil {
			fmt.Fprintf(w, "ParseForm() err: %v", err)
			return
		}
		nsgId = r.FormValue("nsgid")
		dstPort = r.FormValue("dstport")
		ruleName = r.FormValue("rulename")
		ruleNumberStr = r.FormValue("rulenumber")
	default:
		nsgId = os.Getenv("NSG_ID")
		dstPort = os.Getenv("DST_PORT")
		ruleName = os.Getenv("RULE_NAME")
		ruleNumberStr = os.Getenv("RULE_NUMBER")

	}
	ruleNumber, err := strconv.Atoi(ruleNumberStr)
	if err != nil {
		log.Fatal(err)
	}

	// Get client's IP address
	if r.Header.Get("X-Forwarded-For") != "" {
		ip = strings.Split(r.Header.Get("X-Forwarded-For"), ":")[0]
	} else if r.Header.Get("Host") != "" {
		ip = strings.Split(r.Header.Get("Host"), ":")[0]
	} else if r.RemoteAddr != "" {
		ip = strings.Split(r.RemoteAddr, ":")[0]
	}

	// validate if provided NSG Id is valid
	if !validateResId(nsgId) {
		log.Fatal("Invalid NSG Id")
	}

	// parse nsgId and get subscriptionId, resourceGroup, nsgName
	subscriptionId, resourceGroup, _, resourceName := parseResourceId(nsgId)

	ctx := context.Background()

	networkClientFactory, err = armnetwork.NewClientFactory(subscriptionId, cred, nil)
	if err != nil {
		log.Fatal(err)
	}
	client := networkClientFactory.NewSecurityRulesClient()

	_, err = allowInbound(ctx, client, resourceGroup, resourceName, ruleName, "*", dstPort, "Tcp", ip, "*", int32(ruleNumber))
	if err != nil {
		log.Fatal(err)
	}
	w.Write([]byte(""))
}

// Creates a new allow inbound security rule in NSG
func allowInbound(ctx context.Context, securityRulesClient *armnetwork.SecurityRulesClient, rgName, nsgName, ruleName, dstIp, dstPort, protocol, srcIp, srcPort string, priority int32) (bool, error) {
	log.Println("[INF] Trying to modify", nsgName, "security rule", ruleName)
	var ok bool
	// Check if rule already exists. If it does, appends the new source IP to the existing rule
	securityRule, _ := securityRulesClient.Get(ctx, rgName, nsgName, ruleName, nil)

	//Check if security rule exists and has one or multiple source IP addresses
	var newIps []*string
	var newIp *string

	if securityRule.Properties != nil && securityRule.Properties.SourceAddressPrefix != nil {
		newIps = append(newIps, securityRule.Properties.SourceAddressPrefix)
	} else if securityRule.Properties != nil && securityRule.Properties.SourceAddressPrefixes != nil {
		newIps = append(newIps, securityRule.Properties.SourceAddressPrefixes...)
	}
	newIps = append(newIps, &srcIp)

	// If total number of source IP addresses is less than 2, then set source only to the new IP address
	if len(newIps) <= 1 {
		newIp = &srcIp
		newIps = nil
	}

	// Create or update the security rule
	pollerResp, err := securityRulesClient.BeginCreateOrUpdate(ctx,
		rgName,
		nsgName,
		ruleName,
		armnetwork.SecurityRule{
			Properties: &armnetwork.SecurityRulePropertiesFormat{
				Access:                   &[]armnetwork.SecurityRuleAccess{armnetwork.SecurityRuleAccessAllow}[0],
				DestinationAddressPrefix: &[]string{dstIp}[0],
				DestinationPortRange:     &[]string{dstPort}[0],
				Direction:                &[]armnetwork.SecurityRuleDirection{armnetwork.SecurityRuleDirectionInbound}[0],
				Priority:                 &[]int32{priority}[0],
				Protocol:                 &[]armnetwork.SecurityRuleProtocol{armnetwork.SecurityRuleProtocol(protocol)}[0],
				SourceAddressPrefix:      newIp,
				SourceAddressPrefixes:    newIps,
				SourcePortRange:          &[]string{srcPort}[0],
			},
		},
		nil)

	if err != nil {
		return ok, fmt.Errorf("cannot create security rule: %v", err)
	}

	// Wait for the operation to finish using the poller
	_, err = pollerResp.PollUntilDone(ctx, nil)
	// Used for debugging
	if err != nil {
		return ok, fmt.Errorf("cannot get security rule create or update future response: %v", err)
	}
	log.Println("[INF] Successfully added", srcIp, "to", nsgName, "security rule", ruleName)
	return true, nil
}

// Login to Azure, using different kind of methods - credentials, managed identity
func azureLogin() (cred *azidentity.ChainedTokenCredential, err error) {
	managedCred, _ := azidentity.NewManagedIdentityCredential(nil)
	cliCred, _ := azidentity.NewAzureCLICredential(nil)
	envCred, _ := azidentity.NewEnvironmentCredential(nil)
	// If connection to 169.254.169.254 - skip Managed Identity Credentials
	if _, tcpErr := net.Dial("tcp", "169.254.169.254:80"); tcpErr != nil {
		cred, err = azidentity.NewChainedTokenCredential([]azcore.TokenCredential{cliCred, envCred}, nil)
	} else {
		cred, err = azidentity.NewChainedTokenCredential([]azcore.TokenCredential{managedCred, cliCred, envCred}, nil)
	}

	return cred, err
}

func main() {
	login, err := azureLogin()
	if err != nil {
		log.Fatal("[ERR] : Failed to login:\n", err)
	}
	httpInvokerPort, exists := os.LookupEnv("HTTP_PORT")
	if exists {
		fmt.Println("HTTP_PORT: " + httpInvokerPort)
	} else {
		httpInvokerPort = "8080"
	}
	mux := http.NewServeMux()
	// Make default hander which returns default.html
	mux.HandleFunc("/", defaultHandler)
	mux.HandleFunc("/whitelistip", func(w http.ResponseWriter, r *http.Request) {
		whitelistipHandler(w, r, login)
	})
	mux.HandleFunc("/myip", myIpHandler)
	log.Println("[INF] Listening on port", httpInvokerPort)
	log.Fatal(http.ListenAndServe(":"+httpInvokerPort, mux))
}
