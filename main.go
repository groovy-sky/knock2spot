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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
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
	resourceId = strings.ToLower(resourceId)
	// takes Azure resource Id and parses sub id, group, resource type and name
	parts := strings.Split(resourceId, "/")
	subscriptionId = parts[2]
	resourceGroup = parts[4]
	resourceProvider = strings.Join(parts[6:8], "/")
	resourceName = parts[8]
	return subscriptionId, resourceGroup, resourceProvider, resourceName
}

// Draws default page which contains links to all related pages
// Also contains a form to submit data to whitelistipHandler
func defaultHandler(w http.ResponseWriter, r *http.Request) {
	ip := parseIp(r)
	w.Write([]byte(`
	<!DOCTYPE html>
	<html>
	<head>
		<title>knock2spot</title>
		<link rel="icon" type="image/x-icon" href="https://raw.githubusercontent.com/groovy-sky/knock2spot/master/logo.svg">
		<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/normalize/8.0.1/normalize.min.css">
		<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/skeleton/2.0.4/skeleton.min.css">
		<style>
			/* Your custom CSS styles here */
			form {
				margin: 20px;
				padding: 10px;
				display: inline-block;
			}
			big {
				margin: 5px;
				align: center;
				style: bold;
			}
			fieldset {
				border: none;
				box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
				margin-bottom: 10px;
				padding: 5px;
				width: 20%; 
			}
			fieldset:nth-child(odd) {
				background-color: #f5f5f5; /* Lighter color for odd fieldsets */
			}
			fieldset:nth-child(even) {
				background-color: #ebebeb; /* Darker color for even fieldsets */
			}
		</style>
	</head>
	<body>
		<fieldset>	
			<form action="whitelistip" method="POST">
			<legend>Whitelist IP for NSG</legend>
				<label for="resid">NSG's ID:</label>
				<input type="text" id="resid" name="resid" value="" required /><br>
				<label for="dstport">Destination's Port:</label>
				<input type="text" id="dstport" value="" name="dstport" required /><br>
				<label for="rulenumber">Security Rule Number:</label>
				<input type="text" id="rulenumber" name="rulenumber" value="" required><br>
				<label for="rulename">Security Rule Name:</label>
				<input type="text" id="rulename" name="rulename" value="" required><br>
				<input type="submit" value="Submit">
			</form>
		</fieldset>
		<fieldset>
			<form action="whitelistip" method="POST">
			<legend>Whitelist IP for PaaS</legend>
				<label for="resid">PaaS resource's ID:</label>
				<input type="text" id="resid" name="resid" value="" required /><br>
				<input type="submit" value="Submit">
			</form>
		</fieldset>
		<fieldset>
			<big>Detected IP:` + ip + `</big>
		</fieldset>
	</body>
	</html>
	`))
}

// Parse IP from X-Forwarded-For, Host or RemoteAddr headers
func parseIp(r *http.Request) (ip string) {
	if r.Header.Get("X-Forwarded-For") != "" {
		ip = strings.Split(r.Header.Get("X-Forwarded-For"), ":")[0]
	} else if r.Header.Get("Host") != "" {
		ip = strings.Split(r.Header.Get("Host"), ":")[0]
	} else if r.RemoteAddr != "" {
		ip = strings.Split(r.RemoteAddr, ":")[0]
	}
	return ip
}

// Returns client's IP address
func myIpHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(parseIp(r)))
}

// Takes incoming IP address and adds it to NSG
func whitelistipHandler(w http.ResponseWriter, r *http.Request, cred *azidentity.ChainedTokenCredential) {
	var ip, resid, dstPort, ruleName, ruleNumberStr string
	var err error
	var resids []string

	// Create context
	ctx := context.Background()

	// Get the request body and parse input data generated from default.html in case of POST request
	switch r.Method {
	case "POST":
		if err := r.ParseForm(); err != nil {
			log.Fatal("[ERR] Invalid Parsing of Form")
		}
		resid = r.FormValue("resid")
		dstPort = r.FormValue("dstport")
		ruleName = r.FormValue("rulename")
		ruleNumberStr = r.FormValue("rulenumber")
	default:
		resid = os.Getenv("RES_ID")
		dstPort = os.Getenv("DST_PORT")
		ruleName = os.Getenv("RULE_NAME")
		ruleNumberStr = os.Getenv("RULE_NUMBER")
	}

	// Get client's IP address
	ip = parseIp(r)

	// Checks if resid has semicolon in it. If it does - multiple resid's are provided
	// Creates a slice of resid's and iterates over it. If none semicolon is found - slice will contain only one resid
	if strings.Contains(resid, ";") {
		resids = strings.Split(resid, ";")
	} else {
		resids = []string{resid}
	}

	for _, resid := range resids {
		// validate if provided Resource Id is valid
		if !validateResId(resid) {
			log.Fatal("[ERR] Invalid Resource Id")
		}

		// parse resid and get subscriptionId, resourceGroup, nsgName
		subscriptionId, resourceGroup, resourceType, resourceName := parseResourceId(resid)

		switch resourceType {
		case "microsoft.network/networksecuritygroups":
			var networkClientFactory *armnetwork.ClientFactory
			ruleNumber, err := strconv.Atoi(ruleNumberStr)
			if err != nil {
				log.Fatal(err)
			}
			networkClientFactory, err = armnetwork.NewClientFactory(subscriptionId, cred, nil)
			if err != nil {
				log.Fatal(err)
			}
			client := networkClientFactory.NewSecurityRulesClient()

			_, err = addNsgRule(ctx, client, resourceGroup, resourceName, ruleName, "*", dstPort, "Tcp", ip, "*", int32(ruleNumber))

		case "microsoft.storage/storageaccounts":
			storageAccountsClient, err := armstorage.NewAccountsClient(subscriptionId, cred, nil)

			if err != nil {
				log.Fatal(err)
			}
			_, err = addStorageRule(ctx, storageAccountsClient, resourceGroup, resourceName, ip)
		default:
			log.Fatal("[ERR] Invalid Resource Type")
		}
		if err != nil {
			log.Fatal(err)
		} else {
			log.Println("[INF] IP", ip, "whitelisted for", resid)
			w.Write([]byte(""))
		}
	}
}

// Creates a new rule in Storage Account Firewall
func addStorageRule(ctx context.Context, storageAccountsClient *armstorage.AccountsClient, rgName, storageAccountName, ip string) (bool, error) {
	var newIpRuleSet []*armstorage.IPRule
	var newIps []*string

	log.Println("[INF] Trying to modify", storageAccountName, "storage account")
	var ok bool
	// Check if rule already exists. If it does, appends the new source IP to the existing rule
	storageAccount, err := storageAccountsClient.GetProperties(ctx, rgName, storageAccountName, &armstorage.AccountsClientGetPropertiesOptions{Expand: nil})

	if err != nil {
		log.Fatal("[ERR] Cannot get storage account properties: ", err)
	}

	if storageAccount.Properties != nil && storageAccount.Properties.NetworkRuleSet != nil && storageAccount.Properties.NetworkRuleSet.IPRules != nil {
		for _, ipRule := range storageAccount.Properties.NetworkRuleSet.IPRules {
			newIps = append(newIps, ipRule.IPAddressOrRange)
		}
	}

	// Check if IP is already whitelisted
	for _, oldIp := range newIps {
		if *oldIp == ip {
			log.Println("[INF] IP", ip, "is already whitelisted")
			return ok, nil
		}
	}
	newIps = append(newIps, &ip)

	for _, ip := range newIps {
		newRule := &armstorage.IPRule{
			Action:           &[]string{"Allow"}[0],
			IPAddressOrRange: ip,
		}
		newIpRuleSet = append(newIpRuleSet, []*armstorage.IPRule{newRule}...)

	}

	storageAccount.Properties.NetworkRuleSet.IPRules = newIpRuleSet

	// Disable full access and limit to certain IPs
	storageAccount.Properties.NetworkRuleSet.DefaultAction = &[]armstorage.DefaultAction{armstorage.DefaultActionDeny}[0]
	storageAccount.Properties.PublicNetworkAccess = &[]armstorage.PublicNetworkAccess{armstorage.PublicNetworkAccessEnabled}[0]

	// Create or update the security rule
	_, err = storageAccountsClient.Update(ctx,
		rgName,
		storageAccountName,
		armstorage.AccountUpdateParameters{Properties: &armstorage.AccountPropertiesUpdateParameters{NetworkRuleSet: storageAccount.Properties.NetworkRuleSet, PublicNetworkAccess: storageAccount.Properties.PublicNetworkAccess}},
		nil)

	if err != nil {
		return ok, fmt.Errorf("[ERR] Couldn't whitelist IP: %v", err)
	}
	return true, nil
}

// Creates a new allow inbound security rule in NSG
func addNsgRule(ctx context.Context, securityRulesClient *armnetwork.SecurityRulesClient, rgName, nsgName, ruleName, dstIp, dstPort, protocol, srcIp, srcPort string, priority int32) (bool, error) {
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

	// removes duplicates from the slice
	seen := make(map[string]bool)
	j := 0
	for _, v := range newIps {
		if _, ok := seen[*v]; ok {
			continue
		}
		seen[*v] = true
		newIps[j] = v
		j++
	}
	newIps = newIps[:j]

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
	return true, nil
}

// Login to Azure, using different kind of methods - credentials, managed identity
func azureLogin() (cred *azidentity.ChainedTokenCredential, err error) {
	// Create credentials using Managed Identity, Azure CLI, Environment variables
	manCred, _ := azidentity.NewManagedIdentityCredential(nil)
	cliCred, _ := azidentity.NewAzureCLICredential(nil)
	envCred, _ := azidentity.NewEnvironmentCredential(nil)
	// If connection to 169.254.169.254 - skip Managed Identity Credentials
	if _, tcpErr := net.Dial("tcp", "169.254.169.254:80"); tcpErr != nil {
		cred, err = azidentity.NewChainedTokenCredential([]azcore.TokenCredential{cliCred, envCred}, nil)
	} else {
		cred, err = azidentity.NewChainedTokenCredential([]azcore.TokenCredential{manCred}, nil)
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
	mux.HandleFunc("/", defaultHandler)
	mux.HandleFunc("/whitelistip", func(w http.ResponseWriter, r *http.Request) {
		whitelistipHandler(w, r, login)
	})
	mux.HandleFunc("/myip", myIpHandler)
	log.Println("[INF] Listening on port", httpInvokerPort)
	log.Fatal(http.ListenAndServe(":"+httpInvokerPort, mux))
}
