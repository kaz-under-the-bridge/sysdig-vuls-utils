package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/cache"
	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/config"
	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/output"
	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/sysdig"
)

const version = "1.0.0"

func main() {
	var (
		configFile         = flag.String("config", "", "Path to configuration file")
		apiToken           = flag.String("token", "", "Sysdig API token")
		apiURL             = flag.String("url", "https://us2.app.sysdig.com", "Sysdig API base URL")
		command            = flag.String("command", "list", "Command to execute: list, get, update, filter, summary, cache, pipeline, runtime, pipeline-cache, runtime-cache, scan-details, accepted-risks")
		vulnID             = flag.String("id", "", "Vulnerability ID (required for get/update commands)")
		resultID           = flag.String("result-id", "", "Scan Result ID (required for scan-details command)")
		severity           = flag.String("severity", "", "Filter by severity (critical,high,medium,low)")
		fixableOnly        = flag.Bool("fixable", false, "Show only fixable vulnerabilities")
		exploitable        = flag.Bool("exploitable", false, "Show only exploitable vulnerabilities")
		cachePath          = flag.String("cache", "./cache/vulnerabilities.db", "Path to cache file")
		cacheType          = flag.String("cache-type", "sqlite", "Cache type: sqlite or csv")
		outputFormat       = flag.String("output", "table", "Output format: table, detailed, summary, aws")
		aboveHigh          = flag.Bool("above-high", false, "Show only high and critical severity vulnerabilities")
		onlyNotAccepted    = flag.Bool("only-not-accepted", false, "Show only vulnerabilities not accepted as risks")
		showHelp           = flag.Bool("help", false, "Show help")
		showVersion        = flag.Bool("version", false, "Show version")
		createAcceptance   = flag.String("create-acceptance", "", "Create acceptance for CVE (comma-separated list)")
		expirationDays     = flag.Int("expiration-days", 30, "Expiration days for risk acceptance (default 30)")
		daysPeriod         = flag.Int("days", 7, "Number of days to retrieve results from (default 7, max 14)")
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

	// Validate days period
	if *daysPeriod < 1 || *daysPeriod > 14 {
		log.Fatal("Days period must be between 1 and 14")
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
		err = showPipelineResults(client, *outputFormat, *daysPeriod)
	case "runtime":
		err = showRuntimeResults(client, *outputFormat, *daysPeriod)
	case "pipeline-cache":
		err = cachePipelineResults(client, *cachePath, *daysPeriod)
	case "runtime-cache":
		err = cacheRuntimeResults(client, *cachePath, *daysPeriod)
	case "scan-details":
		if *resultID == "" {
			log.Fatal("Result ID is required for scan-details command")
		}
		err = showScanDetails(client, *resultID, *outputFormat, *aboveHigh, *onlyNotAccepted)
	case "accepted-risks":
		err = showAcceptedRisks(client, *outputFormat)
	case "create-acceptance":
		if *createAcceptance == "" {
			log.Fatal("CVE list is required for create-acceptance command")
		}
		err = createAcceptedRisks(client, *createAcceptance, *expirationDays)
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

func showPipelineResults(client *sysdig.Client, outputFormat string, days int) error {
	fmt.Printf("Getting pipeline scan results (last %d days)...\n", days)
	results, err := client.ListPipelineResultsWithDays(days)
	if err != nil {
		return fmt.Errorf("failed to list pipeline results: %w", err)
	}

	// Create table
	headers := []string{"Created At", "Result ID", "Pull String", "Crit", "High"}
	tableData := [][]string{}

	for _, result := range results {
		// Shorten pull string for better display
		shortPullString := result.PullString
		if len(shortPullString) > 80 {
			shortPullString = shortPullString[:77] + "..."
		}
		// ECRパスの短縮 (Pythonの実装に合わせる)
		if strings.Contains(shortPullString, "dkr.ecr.ap-northeast-1.amazonaws.com") {
			shortPullString = strings.Replace(shortPullString, "dkr.ecr.ap-northeast-1.amazonaws.com", "...", -1)
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
			fmt.Sprintf("%d", result.VulnTotalBySeverity.Critical),
			fmt.Sprintf("%d", result.VulnTotalBySeverity.High),
		})
	}

	fmt.Printf("Found %d pipeline scan results\n\n", len(results))

	// Print table manually for better formatting
	fmt.Printf("%-12s %-19s %-80s %-4s %-4s\n", headers[0], headers[1], headers[2], headers[3], headers[4])
	fmt.Println(strings.Repeat("-", 120))

	for _, row := range tableData {
		fmt.Printf("%-12s %-19s %-80s %-4s %-4s\n", row[0], row[1], row[2], row[3], row[4])
	}

	return nil
}

func showRuntimeResults(client *sysdig.Client, outputFormat string, days int) error {
	fmt.Printf("Getting runtime scan results (last %d days)...\n", days)
	results, err := client.ListRuntimeResultsWithDays(days)
	if err != nil {
		return fmt.Errorf("failed to list runtime results: %w", err)
	}

	// Create table
	headers := []string{"Result ID", "aws account", "workload", "name", "Crit", "High"}
	tableData := [][]string{}

	// Pythonの実装に合わせて重複除去
	nameArray := make(map[string]bool)

	for _, result := range results {
		// Extract AWS information from scope
		awsAccount := ""
		workload := ""
		name := ""

		if scope := result.Scope; scope != nil {
			if acc, ok := scope["aws.account.name"].(string); ok {
				awsAccount = acc
			}

			// Determine workload type and name (Pythonの実装に合わせる)
			if clusterName, ok := scope["aws.ecs.cluster.name"].(string); ok {
				workload = "ecs"
				if containerName, ok := scope["aws.ecs.task.container.name"].(string); ok {
					name = fmt.Sprintf("%s/%s", clusterName, containerName)
				} else {
					name = clusterName
				}
			} else if lambdaName, ok := scope["aws.lambda.name"].(string); ok {
				workload = "lambda"
				name = lambdaName
			} else if hostName, ok := scope["host.hostName"].(string); ok {
				workload = "host"
				name = hostName
			}
		}

		// Pythonの実装に合わせて重複チェック
		uniqueKey := fmt.Sprintf("%s:%s", awsAccount, name)
		if nameArray[uniqueKey] {
			continue
		}
		nameArray[uniqueKey] = true

		resultIDShort := result.ResultID
		if len(resultIDShort) >= 16 {
			resultIDShort = resultIDShort[:16] + "..."
		}

		tableData = append(tableData, []string{
			resultIDShort,
			awsAccount,
			workload,
			name,
			fmt.Sprintf("%d", result.VulnTotalBySeverity.Critical),
			fmt.Sprintf("%d", result.VulnTotalBySeverity.High),
		})
	}

	fmt.Printf("Found %d unique runtime scan results\n\n", len(tableData))

	// Print table manually for better formatting
	fmt.Printf("%-19s %-20s %-12s %-30s %-4s %-4s\n", headers[0], headers[1], headers[2], headers[3], headers[4], headers[5])
	fmt.Println(strings.Repeat("-", 100))

	for _, row := range tableData {
		fmt.Printf("%-19s %-20s %-12s %-30s %-4s %-4s\n", row[0], row[1], row[2], row[3], row[4], row[5])
	}

	return nil
}

func showScanDetails(client *sysdig.Client, resultID string, outputFormat string, aboveHigh bool, onlyNotAccepted bool) error {
	fmt.Printf("Getting scan result details for: %s\n", resultID)
	details, err := client.GetScanResultDetails(resultID)
	if err != nil {
		return fmt.Errorf("failed to get scan result details: %w", err)
	}

	fmt.Printf("Scan result contains %d vulnerabilities\n", len(details.Vulnerabilities))

	// Create table for detailed vulnerability info (Pythonの実装に合わせる)
	headers := []string{"Vulnerability Name", "Package Name", "Package Path", "Severity", "Vuln Age"}
	tableData := [][]string{}

	for _, vuln := range details.Vulnerabilities {
		// Get package information
		packageInfo, exists := details.Packages[vuln.PackageRef]
		packageName := "-"
		packagePath := "-"
		if exists {
			packageName = packageInfo.Name
			packagePath = packageInfo.Path
		}

		// Calculate vulnerability age (Pythonの実装に合わせる)
		vulnAge := "-"
		if vuln.DisclosureDate != "" {
			// 簡単な計算（実際のPython実装では日数計算している）
			vulnAge = vuln.DisclosureDate
		}

		tableData = append(tableData, []string{
			vuln.Name,
			packageName,
			packagePath,
			vuln.Severity,
			vulnAge,
		})
	}

	// Print PullString info if available
	if details.Metadata.PullString != "" {
		shortPullString := details.Metadata.PullString
		if strings.Contains(shortPullString, "dkr.ecr.ap-northeast-1.amazonaws.com") {
			shortPullString = strings.Replace(shortPullString, "dkr.ecr.ap-northeast-1.amazonaws.com", "...", -1)
		}
		fmt.Printf("AccessURL: https://us2.app.sysdig.com/secure/#/vulnerabilities/results/%s/overview\n", resultID)
		fmt.Printf("PullString: %s\n\n", shortPullString)
	}

	// Print table manually for better formatting
	fmt.Printf("%-20s %-30s %-30s %-10s %-15s\n", headers[0], headers[1], headers[2], headers[3], headers[4])
	fmt.Println(strings.Repeat("-", 110))

	for _, row := range tableData {
		fmt.Printf("%-20s %-30s %-30s %-10s %-15s\n", row[0], row[1], row[2], row[3], row[4])
	}

	return nil
}

func showAcceptedRisks(client *sysdig.Client, outputFormat string) error {
	fmt.Println("Getting accepted risks...")
	risks, err := client.ListAcceptedRisks()
	if err != nil {
		return fmt.Errorf("failed to list accepted risks: %w", err)
	}

	// Create table
	headers := []string{"Entity Value", "Expiration Date", "Description"}
	tableData := [][]string{}

	for _, risk := range risks {
		tableData = append(tableData, []string{
			risk.EntityValue,
			risk.ExpirationDate,
			risk.Description,
		})
	}

	fmt.Printf("Found %d accepted risks\n\n", len(risks))

	// Print table manually for better formatting
	fmt.Printf("%-20s %-15s %-50s\n", headers[0], headers[1], headers[2])
	fmt.Println(strings.Repeat("-", 90))

	for _, row := range tableData {
		fmt.Printf("%-20s %-15s %-50s\n", row[0], row[1], row[2])
	}

	return nil
}

func createAcceptedRisks(client *sysdig.Client, cveList string, expirationDays int) error {
	fmt.Printf("Creating accepted risks for: %s\n", cveList)

	// Get existing accepted risks to avoid duplicates
	existingRisks, err := client.ListAcceptedRisks()
	if err != nil {
		return fmt.Errorf("failed to check existing risks: %w", err)
	}

	// Create map for quick lookup
	existingMap := make(map[string]bool)
	for _, risk := range existingRisks {
		existingMap[risk.EntityValue] = true
	}

	// Parse CVE list
	cves := strings.Split(cveList, ",")
	for _, cve := range cves {
		cve = strings.TrimSpace(cve)
		if cve == "" {
			continue
		}

		if existingMap[cve] {
			fmt.Printf("Already accepted: %s\n", cve)
			continue
		}

		err := client.CreateAcceptedRisk(cve, expirationDays, "ツールによる自動追加")
		if err != nil {
			fmt.Printf("Failed to create accepted risk for %s: %v\n", cve, err)
		} else {
			fmt.Printf("Created accepted risk for: %s\n", cve)
		}
	}

	return nil
}

func cachePipelineResults(client *sysdig.Client, cachePath string, days int) error {
	fmt.Printf("Caching pipeline scan results (last %d days)...\n", days)

	// Get pipeline results
	results, err := client.ListPipelineResultsWithDays(days)
	if err != nil {
		return fmt.Errorf("failed to list pipeline results: %w", err)
	}

	// Filter results to only those with critical or high vulnerabilities
	filteredResults := make([]sysdig.ScanResult, 0)
	for _, result := range results {
		if result.VulnTotalBySeverity.Critical > 0 || result.VulnTotalBySeverity.High > 0 {
			filteredResults = append(filteredResults, result)
			// Limit to 10 for testing as requested in task.md
			if len(filteredResults) >= 10 {
				break
			}
		}
	}

	fmt.Printf("Found %d pipeline scan results (%d with critical/high vulnerabilities, limited to 10 for detailed processing)\n", len(results), len(filteredResults))

	// Get detailed results for each scan result with critical/high vulnerabilities
	detailedResults := make(map[string]*sysdig.DetailedScanResponse)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Process in batches to avoid overwhelming the API
	batchSize := 5
	for i := 0; i < len(filteredResults); i += batchSize {
		end := i + batchSize
		if end > len(filteredResults) {
			end = len(filteredResults)
		}

		for j := i; j < end; j++ {
			wg.Add(1)
			go func(result sysdig.ScanResult) {
				defer wg.Done()
				details, err := client.GetScanResultDetails(result.ResultID)
				if err != nil {
					log.Printf("Failed to get details for result %s: %v", result.ResultID, err)
					return
				}

				mu.Lock()
				detailedResults[result.ResultID] = details
				mu.Unlock()

				fmt.Printf(".")
			}(filteredResults[j])
		}
		wg.Wait()
	}
	fmt.Printf("\nRetrieved details for %d scan results\n", len(detailedResults))

	// Create cache and save results
	scanCache, err := cache.NewScanResultCache(cachePath)
	if err != nil {
		return fmt.Errorf("failed to create scan result cache: %w", err)
	}
	defer scanCache.Close()

	if err := scanCache.SaveScanResults("pipeline", filteredResults, detailedResults); err != nil {
		return fmt.Errorf("failed to save pipeline results to cache: %w", err)
	}

	fmt.Printf("Successfully cached %d pipeline scan results with detailed vulnerability information to %s\n", len(filteredResults), cachePath)
	return nil
}

func cacheRuntimeResults(client *sysdig.Client, cachePath string, days int) error {
	fmt.Printf("Caching runtime scan results (last %d days)...\n", days)

	// Get runtime results
	results, err := client.ListRuntimeResultsWithDays(days)
	if err != nil {
		return fmt.Errorf("failed to list runtime results: %w", err)
	}

	// Filter results to only those with critical or high vulnerabilities
	filteredResults := make([]sysdig.ScanResult, 0)
	for _, result := range results {
		if result.VulnTotalBySeverity.Critical > 0 || result.VulnTotalBySeverity.High > 0 {
			filteredResults = append(filteredResults, result)
			// Limit to 10 for testing as requested in task.md
			if len(filteredResults) >= 10 {
				break
			}
		}
	}

	fmt.Printf("Found %d runtime scan results (%d with critical/high vulnerabilities, limited to 10 for detailed processing)\n", len(results), len(filteredResults))

	// Get detailed results for each scan result with critical/high vulnerabilities
	detailedResults := make(map[string]*sysdig.DetailedScanResponse)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Process in batches to avoid overwhelming the API
	batchSize := 5
	for i := 0; i < len(filteredResults); i += batchSize {
		end := i + batchSize
		if end > len(filteredResults) {
			end = len(filteredResults)
		}

		for j := i; j < end; j++ {
			wg.Add(1)
			go func(result sysdig.ScanResult) {
				defer wg.Done()
				details, err := client.GetScanResultDetails(result.ResultID)
				if err != nil {
					log.Printf("Failed to get details for result %s: %v", result.ResultID, err)
					return
				}

				mu.Lock()
				detailedResults[result.ResultID] = details
				mu.Unlock()

				fmt.Printf(".")
			}(filteredResults[j])
		}
		wg.Wait()
	}
	fmt.Printf("\nRetrieved details for %d scan results\n", len(detailedResults))

	// Create cache and save results
	scanCache, err := cache.NewScanResultCache(cachePath)
	if err != nil {
		return fmt.Errorf("failed to create scan result cache: %w", err)
	}
	defer scanCache.Close()

	if err := scanCache.SaveScanResults("runtime", filteredResults, detailedResults); err != nil {
		return fmt.Errorf("failed to save runtime results to cache: %w", err)
	}

	fmt.Printf("Successfully cached %d runtime scan results with detailed vulnerability information to %s\n", len(filteredResults), cachePath)
	return nil
}
