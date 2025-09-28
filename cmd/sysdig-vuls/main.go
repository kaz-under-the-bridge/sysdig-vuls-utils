package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/cache"
	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/config"
	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/output"
	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/sysdig"
)

const version = "1.0.0"

func main() {
	var (
		configFile   = flag.String("config", "", "Path to configuration file")
		apiToken     = flag.String("token", "", "Sysdig API token")
		apiURL       = flag.String("url", "https://us2.app.sysdig.com", "Sysdig API base URL")
		command      = flag.String("command", "list", "Command to execute: list, get, update, filter, summary, cache, pipeline, runtime, scan-details")
		vulnID       = flag.String("id", "", "Vulnerability ID (required for get/update commands)")
		resultID     = flag.String("result-id", "", "Scan Result ID (required for scan-details command)")
		severity     = flag.String("severity", "", "Filter by severity (critical,high,medium,low)")
		fixableOnly  = flag.Bool("fixable", false, "Show only fixable vulnerabilities")
		exploitable  = flag.Bool("exploitable", false, "Show only exploitable vulnerabilities")
		cachePath    = flag.String("cache", "./cache/vulnerabilities.db", "Path to cache file")
		cacheType    = flag.String("cache-type", "sqlite", "Cache type: sqlite or csv")
		outputFormat = flag.String("output", "table", "Output format: table, detailed, summary, aws")
		showHelp     = flag.Bool("help", false, "Show help")
		showVersion  = flag.Bool("version", false, "Show version")
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
		err = listVulnerabilities(client, *outputFormat)
	case "filter":
		err = filterVulnerabilities(client, *severity, *fixableOnly, *exploitable, *outputFormat)
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
	case "summary":
		err = showSummary(client)
	case "cache":
		err = cacheVulnerabilities(client, *cacheType, *cachePath, *severity, *fixableOnly, *exploitable)
	case "pipeline":
		err = showPipelineResults(client, *outputFormat)
	case "runtime":
		err = showRuntimeResults(client, *outputFormat)
	case "scan-details":
		if *resultID == "" {
			log.Fatal("Result ID is required for scan-details command")
		}
		err = showScanDetails(client, *resultID, *outputFormat)
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
  filter  - List vulnerabilities with filters
  get     - Get details of a specific vulnerability
  update  - Update vulnerability status/information
  summary - Show vulnerability summary
  cache   - Cache vulnerabilities locally (SQLite or CSV)

Filter Options:
  -severity string
        Filter by severity (critical,high,medium,low)
  -fixable
        Show only fixable vulnerabilities
  -exploitable
        Show only exploitable vulnerabilities

Output Options:
  -output string
        Output format: table, detailed, summary, aws (default "table")

Cache Options:
  -cache string
        Path to cache file (default "./cache/vulnerabilities.db")
  -cache-type string
        Cache type: sqlite or csv (default "sqlite")

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

func listVulnerabilities(client *sysdig.Client, outputFormat string) error {
	fmt.Println("Listing vulnerabilities...")
	vulnerabilities, err := client.ListVulnerabilities()
	if err != nil {
		return fmt.Errorf("failed to list vulnerabilities: %w", err)
	}

	tw := output.NewTableWriter(os.Stdout)

	switch outputFormat {
	case "detailed":
		return tw.WriteDetailedVulnerabilities(vulnerabilities)
	case "summary":
		return tw.WriteSummary(vulnerabilities)
	case "aws":
		return tw.WriteAWSResourceTable(vulnerabilities)
	default:
		return tw.WriteVulnerabilities(vulnerabilities)
	}
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

func filterVulnerabilities(client *sysdig.Client, severity string, fixableOnly, exploitable bool, outputFormat string) error {
	fmt.Println("Filtering vulnerabilities...")

	// Build filter
	filter := sysdig.VulnerabilityFilter{}

	if severity != "" {
		severities := strings.Split(severity, ",")
		filter.Severity = severities
	}

	if fixableOnly {
		fixable := true
		filter.Fixable = &fixable
	}

	if exploitable {
		exp := true
		filter.Exploitable = &exp
	}

	// Use convenience method for critical/high fixable exploitable
	var vulnerabilities []sysdig.Vulnerability
	var err error

	if len(filter.Severity) == 0 && fixableOnly && exploitable {
		// Use the convenience method for common use case
		vulnerabilities, err = client.ListCriticalAndHighVulnerabilities()
	} else {
		vulnerabilities, err = client.ListVulnerabilitiesWithFilters(filter)
	}

	if err != nil {
		return fmt.Errorf("failed to filter vulnerabilities: %w", err)
	}

	tw := output.NewTableWriter(os.Stdout)

	switch outputFormat {
	case "detailed":
		return tw.WriteDetailedVulnerabilities(vulnerabilities)
	case "summary":
		return tw.WriteSummary(vulnerabilities)
	case "aws":
		return tw.WriteAWSResourceTable(vulnerabilities)
	default:
		return tw.WriteVulnerabilities(vulnerabilities)
	}
}

func showSummary(client *sysdig.Client) error {
	fmt.Println("Getting vulnerability summary...")
	vulnerabilities, err := client.ListVulnerabilities()
	if err != nil {
		return fmt.Errorf("failed to list vulnerabilities: %w", err)
	}

	tw := output.NewTableWriter(os.Stdout)
	return tw.WriteSummary(vulnerabilities)
}

func cacheVulnerabilities(client *sysdig.Client, cacheTypeStr, cachePath, severity string, fixableOnly, exploitable bool) error {
	fmt.Println("Caching vulnerabilities...")

	// Build filter
	filter := sysdig.VulnerabilityFilter{}

	if severity != "" {
		severities := strings.Split(severity, ",")
		filter.Severity = severities
	}

	if fixableOnly {
		fixable := true
		filter.Fixable = &fixable
	}

	if exploitable {
		exp := true
		filter.Exploitable = &exp
	}

	// Get vulnerabilities
	var vulnerabilities []sysdig.Vulnerability
	var err error

	if len(filter.Severity) > 0 || fixableOnly || exploitable {
		vulnerabilities, err = client.ListVulnerabilitiesWithFilters(filter)
	} else {
		vulnerabilities, err = client.ListVulnerabilities()
	}

	if err != nil {
		return fmt.Errorf("failed to list vulnerabilities: %w", err)
	}

	// Create cache
	var cacheT cache.CacheType
	switch cacheTypeStr {
	case "sqlite":
		cacheT = cache.CacheTypeSQLite
	case "csv":
		cacheT = cache.CacheTypeCSV
	default:
		return fmt.Errorf("unsupported cache type: %s", cacheTypeStr)
	}

	c, err := cache.NewCache(cacheT, cachePath)
	if err != nil {
		return fmt.Errorf("failed to create cache: %w", err)
	}
	defer c.Close()

	// Save to cache
	if err := c.Save(vulnerabilities); err != nil {
		return fmt.Errorf("failed to save to cache: %w", err)
	}

	fmt.Printf("Successfully cached %d vulnerabilities to %s\n", len(vulnerabilities), cachePath)
	return nil
}

func showPipelineResults(client *sysdig.Client, outputFormat string) error {
	fmt.Println("Getting pipeline scan results...")
	results, err := client.ListPipelineResults()
	if err != nil {
		return fmt.Errorf("failed to list pipeline results: %w", err)
	}

	// Create table
	headers := []string{"Created At", "Result ID", "Pull String", "Policy", "Crit", "High", "Medium", "Low"}
	tableData := [][]string{}

	for _, result := range results {
		// Shorten pull string for better display
		shortPullString := result.PullString
		if len(shortPullString) > 80 {
			shortPullString = shortPullString[:77] + "..."
		}

		policy := "✓"
		if result.PolicyEvaluationResult == "failed" {
			policy = "✗"
		}

		// Safe string truncation
		createdAt := result.CreatedAt
		if len(createdAt) >= 10 {
			createdAt = createdAt[:10]
		}

		resultIDShort := result.ResultID
		if len(resultIDShort) >= 16 {
			resultIDShort = resultIDShort[:16] + "..."
		}

		tableData = append(tableData, []string{
			createdAt,
			resultIDShort,
			shortPullString,
			policy,
			fmt.Sprintf("%d", result.VulnTotalBySeverity["critical"]),
			fmt.Sprintf("%d", result.VulnTotalBySeverity["high"]),
			fmt.Sprintf("%d", result.VulnTotalBySeverity["medium"]),
			fmt.Sprintf("%d", result.VulnTotalBySeverity["low"]),
		})
	}

	fmt.Printf("Found %d pipeline scan results\n\n", len(results))

	// Print table manually for better formatting
	fmt.Printf("%-12s %-19s %-80s %-6s %-4s %-4s %-6s %-4s\n", headers[0], headers[1], headers[2], headers[3], headers[4], headers[5], headers[6], headers[7])
	fmt.Println(strings.Repeat("-", 150))

	for _, row := range tableData {
		fmt.Printf("%-12s %-19s %-80s %-6s %-4s %-4s %-6s %-4s\n", row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7])
	}

	return nil
}

func showRuntimeResults(client *sysdig.Client, outputFormat string) error {
	fmt.Println("Getting runtime scan results...")
	results, err := client.ListRuntimeResults()
	if err != nil {
		return fmt.Errorf("failed to list runtime results: %w", err)
	}

	// Create table
	headers := []string{"Created At", "Result ID", "AWS Account", "Resource Type", "Resource Name", "Crit", "High", "Medium", "Low"}
	tableData := [][]string{}

	for _, result := range results {
		// Extract AWS information from scope
		awsAccount := ""
		resourceType := ""
		resourceName := ""

		if scope := result.Scope; scope != nil {
			if acc, ok := scope["aws.account.name"].(string); ok {
				awsAccount = acc
			}

			// Determine resource type and name
			if clusterName, ok := scope["aws.ecs.cluster.name"].(string); ok {
				resourceType = "ECS"
				if containerName, ok := scope["aws.ecs.task.container.name"].(string); ok {
					resourceName = fmt.Sprintf("%s/%s", clusterName, containerName)
				} else {
					resourceName = clusterName
				}
			} else if lambdaName, ok := scope["aws.lambda.name"].(string); ok {
				resourceType = "Lambda"
				resourceName = lambdaName
			} else if hostName, ok := scope["host.hostName"].(string); ok {
				resourceType = "Host"
				resourceName = hostName
			}
		}

		// Safe string truncation
		createdAt := result.CreatedAt
		if len(createdAt) >= 10 {
			createdAt = createdAt[:10]
		}

		resultIDShort := result.ResultID
		if len(resultIDShort) >= 16 {
			resultIDShort = resultIDShort[:16] + "..."
		}

		tableData = append(tableData, []string{
			createdAt,
			resultIDShort,
			awsAccount,
			resourceType,
			resourceName,
			fmt.Sprintf("%d", result.VulnTotalBySeverity["critical"]),
			fmt.Sprintf("%d", result.VulnTotalBySeverity["high"]),
			fmt.Sprintf("%d", result.VulnTotalBySeverity["medium"]),
			fmt.Sprintf("%d", result.VulnTotalBySeverity["low"]),
		})
	}

	fmt.Printf("Found %d runtime scan results\n\n", len(results))

	// Print table manually for better formatting
	fmt.Printf("%-12s %-19s %-20s %-12s %-30s %-4s %-4s %-6s %-4s\n", headers[0], headers[1], headers[2], headers[3], headers[4], headers[5], headers[6], headers[7], headers[8])
	fmt.Println(strings.Repeat("-", 130))

	for _, row := range tableData {
		fmt.Printf("%-12s %-19s %-20s %-12s %-30s %-4s %-4s %-6s %-4s\n", row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8])
	}

	return nil
}

func showScanDetails(client *sysdig.Client, resultID string, outputFormat string) error {
	fmt.Printf("Getting scan result details for: %s\n", resultID)
	details, err := client.GetScanResultDetails(resultID)
	if err != nil {
		return fmt.Errorf("failed to get scan result details: %w", err)
	}

	fmt.Printf("Scan result contains %d vulnerabilities\n", len(details.Data))

	tw := output.NewTableWriter(os.Stdout)
	return tw.WriteVulnerabilities(details.Data)
}
