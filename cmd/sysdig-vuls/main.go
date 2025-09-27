package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/config"
	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/sysdig"
)

const version = "1.0.0"

func main() {
	var (
		configFile  = flag.String("config", "", "Path to configuration file")
		apiToken    = flag.String("token", "", "Sysdig API token")
		apiURL      = flag.String("url", "https://us2.app.sysdig.com", "Sysdig API base URL")
		command     = flag.String("command", "list", "Command to execute: list, get, update")
		vulnID      = flag.String("id", "", "Vulnerability ID (required for get/update commands)")
		showHelp    = flag.Bool("help", false, "Show help")
		showVersion = flag.Bool("version", false, "Show version")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("sysdig-vuls-utils version %s\n", version)
		return
	}

	if *showHelp {
		printUsage()
		return
	}

	// Load configuration
	cfg, err := config.Load(*configFile, *apiToken, *apiURL)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Validate configuration
	if cfg.APIToken == "" {
		log.Fatal("API token is required. Set via -token flag or SYSDIG_API_TOKEN environment variable")
	}

	// Create Sysdig client
	client := sysdig.NewClient(cfg.APIURL, cfg.APIToken)

	// Execute command
	switch *command {
	case "list":
		err = listVulnerabilities(client)
	case "get":
		if *vulnID == "" {
			log.Fatal("Vulnerability ID is required for get command")
		}
		err = getVulnerability(client, *vulnID)
	case "update":
		if *vulnID == "" {
			log.Fatal("Vulnerability ID is required for update command")
		}
		err = updateVulnerability(client, *vulnID)
	default:
		log.Fatalf("Unknown command: %s", *command)
	}

	if err != nil {
		log.Fatalf("Command failed: %v", err)
	}
}

func printUsage() {
	fmt.Printf(`sysdig-vuls-utils version %s

A tool for managing Sysdig vulnerability data via API.

Usage:
  sysdig-vuls [options]

Options:
  -config string
        Path to configuration file
  -token string
        Sysdig API token (or set SYSDIG_API_TOKEN environment variable)
  -url string
        Sysdig API base URL (default "https://us2.app.sysdig.com")
  -command string
        Command to execute: list, get, update (default "list")
  -id string
        Vulnerability ID (required for get/update commands)
  -help
        Show this help message
  -version
        Show version information

Commands:
  list    - List all vulnerabilities
  get     - Get details of a specific vulnerability
  update  - Update vulnerability status/information

Examples:
  # List all vulnerabilities
  sysdig-vuls -token YOUR_TOKEN -command list

  # Get specific vulnerability
  sysdig-vuls -token YOUR_TOKEN -command get -id CVE-2023-1234

  # Update vulnerability status
  sysdig-vuls -token YOUR_TOKEN -command update -id CVE-2023-1234

Environment Variables:
  SYSDIG_API_TOKEN  - API token for authentication
  SYSDIG_API_URL    - Base URL for Sysdig API

`, version)
}

func listVulnerabilities(client *sysdig.Client) error {
	fmt.Println("Listing vulnerabilities...")
	vulnerabilities, err := client.ListVulnerabilities()
	if err != nil {
		return fmt.Errorf("failed to list vulnerabilities: %w", err)
	}

	fmt.Printf("Found %d vulnerabilities:\n", len(vulnerabilities))
	for _, vuln := range vulnerabilities {
		fmt.Printf("- ID: %s, Severity: %s, Status: %s\n",
			vuln.ID, vuln.Severity, vuln.Status)
	}
	return nil
}

func getVulnerability(client *sysdig.Client, vulnID string) error {
	fmt.Printf("Getting vulnerability: %s\n", vulnID)
	vuln, err := client.GetVulnerability(vulnID)
	if err != nil {
		return fmt.Errorf("failed to get vulnerability: %w", err)
	}

	fmt.Printf("Vulnerability Details:\n")
	fmt.Printf("  ID: %s\n", vuln.ID)
	fmt.Printf("  Severity: %s\n", vuln.Severity)
	fmt.Printf("  Status: %s\n", vuln.Status)
	fmt.Printf("  Description: %s\n", vuln.Description)
	if len(vuln.Packages) > 0 {
		fmt.Printf("  Affected Packages: %v\n", vuln.Packages)
	}
	return nil
}

func updateVulnerability(client *sysdig.Client, vulnID string) error {
	fmt.Printf("Updating vulnerability: %s\n", vulnID)
	// For now, just demonstrate the API call structure
	// In a real implementation, you would gather update parameters
	err := client.UpdateVulnerability(vulnID, map[string]interface{}{
		"status": "reviewed",
	})
	if err != nil {
		return fmt.Errorf("failed to update vulnerability: %w", err)
	}

	fmt.Printf("Successfully updated vulnerability: %s\n", vulnID)
	return nil
}
