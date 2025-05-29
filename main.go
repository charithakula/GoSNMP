package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// SNMPTrapRequest defines the structure for the incoming JSON payload from HTTP requests.
type SNMPTrapRequest struct {
	Sid         string            `json:"sid"`
	SearchName  string            `json:"search_name"`
	App         string            `json:"app"`
	Owner       string            `json:"owner"`
	ResultsLink string            `json:"results_link"`
	Result      map[string]string `json:"result"`
}

// SNMPCredentials defines the structure for SNMP configuration loaded from credentials.json.
type SNMPCredentials struct {
	TargetIP     string `json:"snmp_target_ip"`
	TargetPort   uint16 `json:"snmp_target_port"`
	Version      string `json:"version"`
	Community    string `json:"community,omitempty"`
	SNMPv3User   string `json:"snmpv3_user,omitempty"`
	AuthPassword string `json:"auth_password,omitempty"`
	PrivPassword string `json:"priv_password,omitempty"`
	AuthProtocol string `json:"auth_protocol,omitempty"`
	PrivProtocol string `json:"priv_protocol,omitempty"`
}

// --- Prometheus Metrics ---

var (
	// snmpTrapsSent counts the total number of SNMP traps successfully sent.
	snmpTrapsSent = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "snmp_traps_sent_total",
			Help: "Total number of SNMP traps successfully sent.",
		},
	)
	// snmpTrapFailures counts the total number of SNMP trap send failures.
	snmpTrapFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "snmp_trap_failures_total",
			Help: "Total number of SNMP trap send failures.",
		},
	)
)

// init registers the Prometheus metrics when the package is initialized.
func init() {
	prometheus.MustRegister(snmpTrapsSent, snmpTrapFailures)
}

// --- Credential Loading and Protocol Parsing ---

// loadCredentials reads SNMP configuration from credentials.json.
// It uses os.ReadFile, which is the modern and preferred way over deprecated ioutil.ReadFile.
func loadCredentials() (*SNMPCredentials, error) {
	log.Println("Loading SNMP credentials from credentials.json")

	byteValue, err := os.ReadFile("credentials.json")
	if err != nil {
		log.Printf("Error reading credentials.json: %v", err)
		return nil, fmt.Errorf("failed to read credentials.json: %v", err)
	}

	var creds SNMPCredentials
	if err := json.Unmarshal(byteValue, &creds); err != nil {
		log.Printf("Error unmarshalling credentials.json: %v", err)
		return nil, fmt.Errorf("failed to parse credentials.json: %v", err)
	}

	log.Printf("Successfully loaded SNMP credentials for target %s:%d, version: %s", creds.TargetIP, creds.TargetPort, creds.Version)
	if creds.Version == "v3" {
		log.Printf("  SNMPv3 User: %s, Auth Protocol: %s, Priv Protocol: %s", creds.SNMPv3User, creds.AuthProtocol, creds.PrivProtocol)
	}
	return &creds, nil
}

// parseAuthProtocol converts string protocol names to gosnmp.SnmpV3AuthProtocol.
func parseAuthProtocol(protocol string) gosnmp.SnmpV3AuthProtocol {
	log.Printf("Parsing auth protocol: %s", protocol)
	switch strings.ToUpper(protocol) {
	case "SHA", "SHA1": // Supports common variations like "SHA" or "SHA1"
		return gosnmp.SHA
	case "MD5":
		return gosnmp.MD5
	default:
		log.Printf("Unsupported or empty Auth Protocol '%s'. Defaulting to NoAuth.", protocol)
		return gosnmp.NoAuth
	}
}

// parsePrivProtocol converts string protocol names to gosnmp.SnmpV3PrivProtocol.
func parsePrivProtocol(protocol string) gosnmp.SnmpV3PrivProtocol {
	log.Printf("Parsing priv protocol: %s", protocol)
	switch strings.ToUpper(protocol) {
	case "AES", "AES128": // Supports common variations like "AES" or "AES128"
		return gosnmp.AES
	case "DES":
		return gosnmp.DES
	default:
		log.Printf("Unsupported or empty Priv Protocol '%s'. Defaulting to NoPriv.", protocol)
		return gosnmp.NoPriv
	}
}

// --- SNMP Trap Sending Logic ---

// sendSNMPTrap connects to the SNMP target and sends the trap with the given OIDs.
func sendSNMPTrap(oids []gosnmp.SnmpPDU, version string, creds *SNMPCredentials) error {
	log.Printf("Preparing to send SNMP trap using version: %s to %s:%d", version, creds.TargetIP, creds.TargetPort)

	// Use gosnmp.NewLogger to correctly wrap the standard logger, providing detailed gosnmp logs.
	gosnmpLogger := gosnmp.NewLogger(log.New(os.Stdout, "[GoSNMP] ", log.LstdFlags))

	// Common SNMP parameters for both versions to set initial defaults.
	commonGoSNMP := &gosnmp.GoSNMP{
		Target:  creds.TargetIP,
		Port:    creds.TargetPort,
		Timeout: 5 * time.Second, // Increased timeout for better reliability
		Retries: 3,               // Increased retries for better robustness
		Logger:  gosnmpLogger,    // Inject the gosnmp-wrapped logger
	}

	var g *gosnmp.GoSNMP // This will hold our configured gosnmp client

	switch version {
	case "v2c":
		g = commonGoSNMP
		g.Community = creds.Community
		g.Version = gosnmp.Version2c
		log.Println("Configured SNMP v2c parameters.")
	case "v3":
		g = commonGoSNMP
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel

		// Determine MsgFlags based on configured authentication and privacy protocols.
		authProto := parseAuthProtocol(creds.AuthProtocol)
		privProto := parsePrivProtocol(creds.PrivProtocol)

		var msgFlags gosnmp.SnmpV3MsgFlags
		if authProto != gosnmp.NoAuth && privProto != gosnmp.NoPriv {
			msgFlags = gosnmp.AuthPriv // Both authentication and privacy
			log.Println("MsgFlags set to AuthPriv.")
		} else if authProto != gosnmp.NoAuth && privProto == gosnmp.NoPriv {
			msgFlags = gosnmp.AuthNoPriv // Authentication only
			log.Println("MsgFlags set to AuthNoPriv.")
		} else {
			msgFlags = gosnmp.NoAuthNoPriv // Neither authentication nor privacy (less common for v3)
			log.Println("MsgFlags set to NoAuthNoPriv (unlikely for typical v3 setups with passwords).")
		}
		g.MsgFlags = msgFlags

		// Set SNMPv3 security parameters.
		g.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 creds.SNMPv3User,
			AuthenticationProtocol:   authProto,
			AuthenticationPassphrase: creds.AuthPassword,
			PrivacyProtocol:          privProto,
			PrivacyPassphrase:        creds.PrivPassword,
		}
		log.Println("Configured SNMP v3 parameters.")
	default:
		log.Printf("Unsupported SNMP version: %s", version)
		return fmt.Errorf("unsupported SNMP version: %s", version)
	}

	log.Println("Connecting to SNMP target...")
	if err := g.Connect(); err != nil {
		log.Printf("Error connecting to SNMP target: %v", err)
		snmpTrapFailures.Inc()
		return fmt.Errorf("error connecting to SNMP target: %v", err)
	}
	// Ensure the connection is closed when the function exits.
	defer func() {
		log.Println("Closing SNMP connection.")
		if err := g.Conn.Close(); err != nil {
			log.Printf("Error closing SNMP connection: %v", err)
		}
	}()
	log.Println("Connected successfully to SNMP target.")

	// Construct the SNMP trap with the provided OIDs.
	trap := gosnmp.SnmpTrap{
		Variables: oids,
	}

	log.Printf("Sending SNMP trap with %d OIDs...", len(oids))
	_, err := g.SendTrap(trap)
	if err != nil {
		log.Printf("Error sending SNMP trap: %v", err)
		snmpTrapFailures.Inc()
		return fmt.Errorf("error sending SNMP trap: %v", err)
	}

	log.Println("SNMP trap sent successfully.")
	snmpTrapsSent.Inc() // Increment Prometheus counter for successful traps
	return nil
}

// --- HTTP Handlers and Main Function ---

// sendSNMPTrapHandler processes incoming HTTP requests to send SNMP traps.
func sendSNMPTrapHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Received HTTP request to /send_snmp_trap")

	var trapReq SNMPTrapRequest
	// Use io.ReadAll to read the entire request body bytes.
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close() // Ensure the request body is closed.

	// Unmarshal the JSON request body into the SNMPTrapRequest struct.
	if err := json.Unmarshal(bodyBytes, &trapReq); err != nil {
		log.Printf("Invalid request payload: %v", err)
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	log.Printf("Parsed SNMPTrapRequest: SID=%s, App=%s, Owner=%s", trapReq.Sid, trapReq.App, trapReq.Owner)

	// Load SNMP credentials from credentials.json.
	creds, err := loadCredentials()
	if err != nil {
		log.Printf("Failed to load credentials: %v", err)
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	log.Println("Constructing SNMP OIDs from request data.")
	// Construct the list of SNMP OIDs (Object Identifiers) and their values from the request.
	oids := []gosnmp.SnmpPDU{
		{Name: "1.3.6.1.4.1.12345.1.2.1", Type: gosnmp.OctetString, Value: trapReq.Sid},
		{Name: "1.3.6.1.4.1.12345.1.2.2", Type: gosnmp.OctetString, Value: trapReq.SearchName},
		{Name: "1.3.6.1.4.1.12345.1.2.3", Type: gosnmp.OctetString, Value: trapReq.App},
		{Name: "1.3.6.1.4.1.12345.1.2.4", Type: gosnmp.OctetString, Value: trapReq.Owner},
		{Name: "1.3.6.1.4.1.12345.1.2.5", Type: gosnmp.OctetString, Value: trapReq.ResultsLink},
		{Name: "1.3.6.1.4.1.12345.1.2.6", Type: gosnmp.OctetString, Value: trapReq.Result["hostname"]},
		{Name: "1.3.6.1.4.1.12345.1.2.7", Type: gosnmp.OctetString, Value: trapReq.Result["index"]},
		{Name: "1.3.6.1.4.1.12345.1.2.8", Type: gosnmp.OctetString, Value: trapReq.Result["level"]},
		{Name: "1.3.6.1.4.1.12345.1.2.9", Type: gosnmp.OctetString, Value: trapReq.Result["location"]},
		{Name: "1.3.6.1.4.1.12345.1.2.10", Type: gosnmp.OctetString, Value: trapReq.Result["message"]},
		{Name: "1.3.6.1.4.1.12345.1.2.11", Type: gosnmp.OctetString, Value: trapReq.Result["operation"]},
		{Name: "1.3.6.1.4.1.12345.1.2.12", Type: gosnmp.OctetString, Value: trapReq.Result["requestURL"]},
		{Name: "1.3.6.1.4.1.12345.1.2.13", Type: gosnmp.OctetString, Value: trapReq.Result["service"]},
		{Name: "1.3.6.1.4.1.12345.1.2.14", Type: gosnmp.OctetString, Value: trapReq.Result["source"]},
		{Name: "1.3.6.1.4.1.12345.1.2.15", Type: gosnmp.OctetString, Value: trapReq.Result["sourcetype"]},
		{Name: "1.3.6.1.4.1.12345.1.2.16", Type: gosnmp.OctetString, Value: trapReq.Result["time"]},
	}

	// Send the SNMP trap.
	if err := sendSNMPTrap(oids, creds.Version, creds); err != nil {
		log.Printf("Failed to send SNMP trap: %v", err)
		http.Error(w, "Failed to send SNMP trap", http.StatusInternalServerError)
		return
	}

	log.Println("Returning success response to client.")
	w.Write([]byte("SNMP Trap sent successfully."))
}

// healthHandler provides a simple health check endpoint at /health.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// main function sets up and starts the HTTP server.
func main() {
	log.Println("Starting SNMP Trap HTTP server on port 8080.")

	// Register HTTP handlers for different endpoints.
	http.HandleFunc("/send_snmp_trap", sendSNMPTrapHandler)
	http.HandleFunc("/health", healthHandler)
	http.Handle("/metrics", promhttp.Handler()) // Exposes Prometheus metrics at /metrics

	// Start the HTTP server, listening on port 8080.
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
