package main

import (
	"fmt"
	"log"
	"os"

	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/sysdig"
)

func main() {
	// Get API token from environment variable
	apiToken := os.Getenv("SYSDIG_API_TOKEN")
	if apiToken == "" {
		log.Fatal("SYSDIG_API_TOKEN environment variable is required")
	}

	// Create client
	client := sysdig.NewClient("https://us2.app.sysdig.com", apiToken)

	// Example: List all vulnerabilities
	fmt.Println("Listing vulnerabilities...")
	vulnerabilities, err := client.ListVulnerabilities()
	if err != nil {
		log.Fatalf("Failed to list vulnerabilities: %v", err)
	}

	fmt.Printf("Found %d vulnerabilities\n", len(vulnerabilities))
	for i, vuln := range vulnerabilities {
		if i >= 5 { // Show only first 5 for brevity
			break
		}
		fmt.Printf("- %s: %s (Severity: %s, Status: %s)\n",
			vuln.ID, vuln.Description, vuln.Severity, vuln.Status)
	}

	// Example: Get vulnerabilities by severity
	fmt.Println("\nListing high severity vulnerabilities...")
	highSevVulns, err := client.ListVulnerabilitiesBySeverity("high")
	if err != nil {
		log.Printf("Failed to list high severity vulnerabilities: %v", err)
	} else {
		fmt.Printf("Found %d high severity vulnerabilities\n", len(highSevVulns))
	}
}
