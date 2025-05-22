package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type SNMPTrapRequest struct {
	Sid         string            `json:"sid"`
	SearchName  string            `json:"search_name"`
	App         string            `json:"app"`
	Owner       string            `json:"owner"`
	ResultsLink string            `json:"results_link"`
	Result      map[string]string `json:"result"`
}

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

// --- Metrics ---
var (
	snmpTrapsSent = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "snmp_traps_sent_total",
			Help: "Total number of SNMP traps successfully sent.",
		},
	)
	snmpTrapFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "snmp_trap_failures_total",
			Help: "Total number of SNMP trap send failures.",
		},
	)
)

func init() {
	prometheus.MustRegister(snmpTrapsSent, snmpTrapFailures)
}

func loadCredentials() (*SNMPCredentials, error) {
	log.Println("Loading SNMP credentials from credentials.json")
	file, err := os.Open("credentials.json")
	if err != nil {
		log.Printf("Error opening credentials.json: %v", err)
		return nil, fmt.Errorf("failed to open credentials.json: %v", err)
	}
	defer file.Close()

	var creds SNMPCredentials
	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		log.Printf("Error reading credentials.json: %v", err)
		return nil, fmt.Errorf("failed to read credentials.json: %v", err)
	}
	if err := json.Unmarshal(byteValue, &creds); err != nil {
		log.Printf("Error unmarshalling credentials.json: %v", err)
		return nil, fmt.Errorf("failed to parse credentials.json: %v", err)
	}

	log.Printf("Successfully loaded SNMP credentials for target %s:%d", creds.TargetIP, creds.TargetPort)
	return &creds, nil
}

func parseAuthProtocol(protocol string) gosnmp.SnmpV3AuthProtocol {
	log.Printf("Parsing auth protocol: %s", protocol)
	switch strings.ToUpper(protocol) {
	case "SHA":
		return gosnmp.SHA
	case "MD5":
		return gosnmp.MD5
	default:
		return gosnmp.NoAuth
	}
}

func parsePrivProtocol(protocol string) gosnmp.SnmpV3PrivProtocol {
	log.Printf("Parsing priv protocol: %s", protocol)
	switch strings.ToUpper(protocol) {
	case "AES":
		return gosnmp.AES
	case "DES":
		return gosnmp.DES
	default:
		return gosnmp.NoPriv
	}
}

func sendSNMPTrap(oids []gosnmp.SnmpPDU, version string, creds *SNMPCredentials) error {
	log.Printf("Preparing to send SNMP trap using version: %s", version)
	var g *gosnmp.GoSNMP

	switch version {
	case "v2c":
		g = &gosnmp.GoSNMP{
			Target:    creds.TargetIP,
			Port:      creds.TargetPort,
			Community: creds.Community,
			Version:   gosnmp.Version2c,
			Timeout:   2 * time.Second,
			Retries:   1,
		}
		log.Println("Configured SNMP v2c parameters")
	case "v3":
		g = &gosnmp.GoSNMP{
			Target:        creds.TargetIP,
			Port:          creds.TargetPort,
			Version:       gosnmp.Version3,
			Timeout:       2 * time.Second,
			Retries:       1,
			SecurityModel: gosnmp.UserSecurityModel,
			MsgFlags:      gosnmp.AuthPriv,
			SecurityParameters: &gosnmp.UsmSecurityParameters{
				UserName:                 creds.SNMPv3User,
				AuthenticationProtocol:   parseAuthProtocol(creds.AuthProtocol),
				AuthenticationPassphrase: creds.AuthPassword,
				PrivacyProtocol:          parsePrivProtocol(creds.PrivProtocol),
				PrivacyPassphrase:        creds.PrivPassword,
			},
		}
		log.Println("Configured SNMP v3 parameters")
	default:
		log.Printf("Unsupported SNMP version: %s", version)
		return fmt.Errorf("unsupported SNMP version: %s", version)
	}

	log.Println("Connecting to SNMP target")
	if err := g.Connect(); err != nil {
		log.Printf("Error connecting to SNMP target: %v", err)
		snmpTrapFailures.Inc()
		return fmt.Errorf("error connecting to SNMP target: %v", err)
	}
	defer g.Conn.Close()
	log.Println("Connected successfully to SNMP target")

	if creds.Version == "v3" {
		oid := "1.3.6.1.6.3.10.2.1.1.0" // snmpEngineID
		result, err := g.Get([]string{oid})
		if err != nil {
			log.Printf("Failed to fetch SNMP engine ID: %v", err)
		} else if len(result.Variables) > 0 {
			if engineID, ok := result.Variables[0].Value.([]byte); ok {
				log.Printf("SNMP Engine ID: %x", engineID)
			} else {
				log.Println("Unexpected type for SNMP engine ID")
			}
		}
	}
	trap := gosnmp.SnmpTrap{Variables: oids}
	log.Printf("Sending SNMP trap with %d OIDs", len(oids))
	_, err := g.SendTrap(trap)
	if err != nil {
		log.Printf("Error sending SNMP trap: %v", err)
		snmpTrapFailures.Inc()
		return fmt.Errorf("error sending SNMP trap: %v", err)
	}

	log.Println("SNMP trap sent successfully")
	snmpTrapsSent.Inc()
	return nil
}

func sendSNMPTrapHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Received HTTP request to /send_snmp_trap")

	var trapReq SNMPTrapRequest
	if err := json.NewDecoder(r.Body).Decode(&trapReq); err != nil {
		log.Printf("Invalid request payload: %v", err)
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	log.Printf("Parsed SNMPTrapRequest: SID=%s, App=%s, Owner=%s", trapReq.Sid, trapReq.App, trapReq.Owner)

	creds, err := loadCredentials()
	if err != nil {
		log.Printf("Failed to load credentials: %v", err)
		http.Error(w, "Failed to load credentials", http.StatusInternalServerError)
		return
	}

	log.Println("Constructing SNMP OIDs from request data")
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

	if err := sendSNMPTrap(oids, creds.Version, creds); err != nil {
		log.Printf("Failed to send SNMP trap: %v", err)
		http.Error(w, "Failed to send SNMP trap", http.StatusInternalServerError)
		return
	}

	log.Println("Returning success response to client")
	w.Write([]byte("SNMP Trap sent successfully"))
}

// --- New Health and Metrics Handlers ---
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	log.Println("Starting SNMP Trap HTTP server on port 8080")

	http.HandleFunc("/send_snmp_trap", sendSNMPTrapHandler)
	http.HandleFunc("/health", healthHandler)
	http.Handle("/metrics", promhttp.Handler())

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
