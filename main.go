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
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/messaging/azservicebus"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
)

func sanitazeInput(input string) string {
	// Removes all non-alphanumeric characters from input
	regex := `[^\w\d\.\/\@\;\_\-]`
	r := regexp.MustCompile(regex)
	return r.ReplaceAllString(input, "")
}

// Checks that input matches Azure Resource Id format
func validateResID(input string) bool {
	// Validates that input is valid Azure Resource Id using regex
	regex := `^\/subscriptions\/.{36}\/resourceGroups\/.*\/providers\/[a-zA-Z0-9]*.[a-zA-Z0-9]*\/[a-zA-Z0-9]*\/.*`
	r := regexp.MustCompile(regex)
	return r.MatchString(input)
}

// Gets Azure Resource's names of subscription, group, resource type etc.
func parseresourceID(resourceID string) (subscriptionID, resourceGroup, resourceProvider, resourceName string) {
	resourceID = strings.ToLower(resourceID)
	// takes Azure resource Id and parses sub id, group, resource type and name
	parts := strings.Split(resourceID, "/")
	subscriptionID = parts[2]
	resourceGroup = parts[4]
	resourceProvider = strings.Join(parts[6:8], "/")
	resourceName = parts[8]
	return subscriptionID, resourceGroup, resourceProvider, resourceName
}

// Draws default page which contains links to all related pages
// Also contains a form to submit data to whitelistipHandler
func defaultHandler(w http.ResponseWriter, r *http.Request) {
	ip := parseIP(r)
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
				<input type="checkbox" id="debug" name="debug" value="true" checked><br>
				<label for="debug">Print result</label><br>
				<input type="submit" value="Submit"><br>
			</form>
		</fieldset>
		<fieldset>
			<form action="whitelistip" method="POST">
			<legend>Whitelist IP for PaaS</legend>
				<label for="resid">PaaS resource's ID:</label>
				<input type="text" id="resid" name="resid" value="" required /><br>
				<input type="checkbox" id="debug" name="debug" value="debug" checked><br>
				<label for="debug">Print result</label><br>
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
func parseIP(r *http.Request) (ip string) {
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
func myIPHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("[INF] Handling myip request")
	w.Write([]byte(parseIP(r)))
}

// Takes incoming IP address and adds it to specified resource
func whitelistipHandler(w http.ResponseWriter, r *http.Request, cred *azidentity.ChainedTokenCredential) {
	var ip, resid, dstPort, ruleName, ruleNumberStr, debugFlag string
	var err error
	var resids []string

	log.Println("[INF] Handling whitelistip request")

	// Create context
	ctx := context.Background()

	// Get the request body and parse input data generated from default.html in case of POST request
	// or take data from environment variables in case of GET request
	switch r.Method {
	case "POST":
		if err = r.ParseForm(); err != nil {
			log.Println("[ERR] Invalid Parsing of Form")
			w.Write([]byte("Invalid Parsing of Form"))
			return
		}
		resid = sanitazeInput(r.FormValue("resid"))
		dstPort = sanitazeInput(r.FormValue("dstport"))
		ruleName = sanitazeInput(r.FormValue("rulename"))
		ruleNumberStr = sanitazeInput(r.FormValue("rulenumber"))
		debugFlag = sanitazeInput(r.FormValue("debug"))
	default:
		resid = os.Getenv("RES_ID")
		dstPort = os.Getenv("DST_PORT")
		ruleName = os.Getenv("RULE_NAME")
		ruleNumberStr = os.Getenv("RULE_NUMBER")
		debugFlag = os.Getenv("DEBUG")
	}

	// Get client's IP address
	ip = parseIP(r)

	// Checks if resid has semicolon in it. If it does - multiple resid's are provided
	// Creates a slice of resid's and iterates over it. If none semicolon is found - slice will contain only one resid
	if strings.Contains(resid, ";") {
		resids = strings.Split(resid, ";")
	} else {
		resids = []string{resid}
	}

	for _, resid := range resids {
		// validate if provided Resource Id is valid
		if !validateResID(resid) {
			log.Println("[ERR] Invalid Resource Id")
			return
		}

		// parse resid and get subscriptionID, resourceGroup, nsgName
		subscriptionID, resourceGroup, resourceType, resourceName := parseresourceID(resid)

		switch resourceType {
		case "microsoft.network/networksecuritygroups":
			var networkClientFactory *armnetwork.ClientFactory
			var ruleNumber int
			ruleNumber, err = strconv.Atoi(ruleNumberStr)
			if err != nil {
				log.Println("[ERR] Can't get rule number (will use default): ", err)
				ruleNumber = 4096
			}
			networkClientFactory, err = armnetwork.NewClientFactory(subscriptionID, cred, nil)
			if err != nil {
				log.Println("[ERR] Cannot create network client factory: ", err)
				w.Write([]byte("Cannot create network client factory"))
				return
			}
			client := networkClientFactory.NewSecurityRulesClient()

			_, err = addNsgRule(ctx, client, resourceGroup, resourceName, ruleName, "*", dstPort, "Tcp", ip, "*", int32(ruleNumber))

		case "microsoft.storage/storageaccounts":
			var storageAccountsClient *armstorage.AccountsClient
			storageAccountsClient, err = armstorage.NewAccountsClient(subscriptionID, cred, nil)

			if err != nil {
				w.Write([]byte("Cannot create storage account client"))
				log.Println("[ERR] Cannot create storage account client: ", err)
				return
			}
			_, err = addStorageRule(ctx, storageAccountsClient, resourceGroup, resourceName, ip)
		default:
			err = fmt.Errorf("[ERR] Resource type %s is not supported", resourceType)
		}
		if err != nil {
			log.Println("[ERR] Cannot whitelist IP: ", err)
			w.Write([]byte("Failed to whitelist IP"))
		} else {
			log.Println("[INF] IP", ip, "whitelisted for", resid)
			switch len(debugFlag) {
			case 0:
				w.Write([]byte(""))
			default:
				w.Write([]byte("IP " + ip + " whitelisted for " + resid + "\n"))
			}

		}
	}
}

// Creates a new rule in Storage Account Firewall
func addStorageRule(ctx context.Context, storageAccountsClient *armstorage.AccountsClient, rgName, storageAccountName, ip string) (bool, error) {
	var newIPRuleSet []*armstorage.IPRule
	var newIPs []*string
	var ok bool

	log.Println("[INF] Trying to modify", storageAccountName, "storage account")

	// Check if rule already exists. If it does, appends the new source IP to the existing rule
	storageAccount, err := storageAccountsClient.GetProperties(ctx, rgName, storageAccountName, &armstorage.AccountsClientGetPropertiesOptions{Expand: nil})

	if err != nil {
		return ok, fmt.Errorf("[ERR] Cannot get storage account properties: %v", err)
	}

	if storageAccount.Properties != nil && storageAccount.Properties.NetworkRuleSet != nil && storageAccount.Properties.NetworkRuleSet.IPRules != nil {
		for _, ipRule := range storageAccount.Properties.NetworkRuleSet.IPRules {
			newIPs = append(newIPs, ipRule.IPAddressOrRange)
		}
	}

	// Check if IP is already whitelisted
	for _, oldIP := range newIPs {
		if *oldIP == ip {
			log.Println("[INF] IP", ip, "is already whitelisted")
			return ok, nil
		}
	}
	newIPs = append(newIPs, &ip)

	for _, ip := range newIPs {
		newRule := &armstorage.IPRule{
			Action:           &[]string{"Allow"}[0],
			IPAddressOrRange: ip,
		}
		newIPRuleSet = append(newIPRuleSet, []*armstorage.IPRule{newRule}...)

	}

	storageAccount.Properties.NetworkRuleSet.IPRules = newIPRuleSet

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

// Gets input value and transfer it to Azure Service Bus
func messageHandler(w http.ResponseWriter, r *http.Request, cred *azidentity.ChainedTokenCredential) {
	var message, queue, replyTo, subject, contentType string
	var err error

	log.Println("[INF] Handling Service Bus messaging")

	namespace, ok := os.LookupEnv("AZURE_SERVICEBUS_HOSTNAME")

	if !ok {
		log.Println("[ERR] AZURE_SERVICEBUS_HOSTNAME environment variable is not set")
		w.Write([]byte("No Service Bus specified"))
		return
	}

	// Checks URL and request type. If it is GET and request is for /message - draws default page
	// If it is POST - reads user's input and sends it to Service Bus
	// If it is GET and request is for /message/{queue} - reads message from specified queue
	switch r.Method {
	case "POST":
		// Reads user's input
		message = sanitazeInput(r.FormValue("message"))
		queue = sanitazeInput(r.FormValue("queue"))
		replyTo = sanitazeInput(r.FormValue("replyTo"))
		subject = sanitazeInput(r.FormValue("subject"))
		contentType = sanitazeInput(r.FormValue("contentType"))
	case "GET":
		// Gets queue name from URL
		queue = strings.TrimPrefix(r.URL.Path, "/message/")
		if queue == "" {
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
			<form action="" method="POST">
			<legend>Send message to Service Bus</legend>
				<label for="message">Message:</label>
				<input type="text" id="message" name="message" value="" required /><br>
				<label for="queue">Queue:</label>
				<input type="text" id="queue" value="" name="queue" required /><br>
				<label for="replyTo">ReplyTo:</label>
				<input type="text" id="replyTo" name="replyTo" value="" required><br>
				<label for="subject">Subject:</label>
				<input type="text" id="subject" name="subject" value="" required><br>
				<label for="contentType">Content Type:</label>
				<select id="contentType" name="contentType" required>
					<option value="text/plain">Text</option>
					<option value="application/json">JSON</option>
					<option value="application/xml">XML</option>
				</select><br>
				<input type="submit" value="Submit">
			</form>
		</fieldset>
	</body>
	</html>
	`))
			return
		}
	}

	// Create context
	ctx := context.Background()

	client, err := azservicebus.NewClient(namespace, cred, nil)
	if err != nil {
		log.Fatal(err)
	}
	switch message {
	case "":
		// If message is empty - read message from queue
		receiver, err := client.NewReceiverForQueue(queue, nil)

		if err != nil {
			log.Fatal(err)
		}

		defer receiver.Close(ctx)

		ctxWithTimeout, cancel := context.WithTimeout(ctx, time.Second*5)
		defer cancel()

		messages, err := receiver.ReceiveMessages(ctxWithTimeout, 1, nil)
		if err != nil {
			if err == context.DeadlineExceeded {
				// Handle timeout error
				log.Println("[INF] No new messages. Timeout has been exceeded.")
			} else {
				log.Fatal(err)
			}
		}

		switch len(messages) {
		case 0:
			w.Write([]byte("No new messages in queue"))
		default:
			for i, message := range messages {
				// Complete the message. This will delete the message from the queue.
				receiver.CompleteMessage(ctx, message, nil)
				w.Write([]byte(fmt.Sprintf("Message %d: %s\nReplyTo: %s\nContent Type:%s\nSubject: %s\n", i, message.Body, *message.ReplyTo, *message.ContentType, *message.Subject)))
			}
		}
	default:

		// Create a sender using the client in specified topic
		sender, err := client.NewSender(queue, nil)

		if err != nil {
			log.Fatal(err)
		}

		defer sender.Close(ctx)

		sbMessage := &azservicebus.Message{
			Body:        []byte(message),
			ContentType: &contentType,
			ReplyTo:     &replyTo,
			Subject:     &subject,
		}

		// Send a single message to the topic
		err = sender.SendMessage(ctx, sbMessage, nil)

		if err != nil {
			log.Fatal(err)
		}
	}

}

// Creates a new allow inbound security rule in NSG
func addNsgRule(ctx context.Context, securityRulesClient *armnetwork.SecurityRulesClient, rgName, nsgName, ruleName, dstIP, dstPort, protocol, srcIP, srcPort string, priority int32) (bool, error) {
	log.Println("[INF] Trying to modify", nsgName, "security rule", ruleName)
	var ok bool
	// Check if rule already exists. If it does, appends the new source IP to the existing rule
	securityRule, _ := securityRulesClient.Get(ctx, rgName, nsgName, ruleName, nil)

	//Check if security rule exists and has one or multiple source IP addresses
	var newIPs []*string
	var newIP *string

	if securityRule.Properties != nil && securityRule.Properties.SourceAddressPrefix != nil {
		newIPs = append(newIPs, securityRule.Properties.SourceAddressPrefix)
	} else if securityRule.Properties != nil && securityRule.Properties.SourceAddressPrefixes != nil {
		newIPs = append(newIPs, securityRule.Properties.SourceAddressPrefixes...)
	}
	newIPs = append(newIPs, &srcIP)

	// removes duplicates from the slice
	seen := make(map[string]bool)
	j := 0
	for _, v := range newIPs {
		if _, ok := seen[*v]; ok {
			continue
		}
		seen[*v] = true
		newIPs[j] = v
		j++
	}
	newIPs = newIPs[:j]

	// If total number of source IP addresses is less than 2, then set source only to the new IP address
	if len(newIPs) <= 1 {
		newIP = &srcIP
		newIPs = nil
	}

	// Create or update the security rule
	pollerResp, err := securityRulesClient.BeginCreateOrUpdate(ctx,
		rgName,
		nsgName,
		ruleName,
		armnetwork.SecurityRule{
			Properties: &armnetwork.SecurityRulePropertiesFormat{
				Access:                   &[]armnetwork.SecurityRuleAccess{armnetwork.SecurityRuleAccessAllow}[0],
				DestinationAddressPrefix: &[]string{dstIP}[0],
				DestinationPortRange:     &[]string{dstPort}[0],
				Direction:                &[]armnetwork.SecurityRuleDirection{armnetwork.SecurityRuleDirectionInbound}[0],
				Priority:                 &[]int32{priority}[0],
				Protocol:                 &[]armnetwork.SecurityRuleProtocol{armnetwork.SecurityRuleProtocol(protocol)}[0],
				SourceAddressPrefix:      newIP,
				SourceAddressPrefixes:    newIPs,
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
		cred, err = azidentity.NewChainedTokenCredential([]azcore.TokenCredential{manCred, cliCred, envCred}, nil)
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
		log.Println("HTTP_PORT: " + httpInvokerPort)
	} else {
		httpInvokerPort = "8080"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", defaultHandler)
	mux.HandleFunc("/whitelistip", func(w http.ResponseWriter, r *http.Request) {
		whitelistipHandler(w, r, login)
	})
	mux.HandleFunc("/myip", myIPHandler)
	mux.HandleFunc("/message/", func(w http.ResponseWriter, r *http.Request) {
		messageHandler(w, r, login)
	})
	log.Println("[INF] Listening on port", httpInvokerPort)
	log.Fatal(http.ListenAndServe(":"+httpInvokerPort, mux))
}
