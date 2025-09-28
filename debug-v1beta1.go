package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/sysdig"
)

func main() {
	apiToken := os.Getenv("SYSDIG_API_TOKEN")
	apiURL := os.Getenv("SYSDIG_API_URL")

	if apiToken == "" {
		log.Fatal("SYSDIG_API_TOKEN is required")
	}
	if apiURL == "" {
		apiURL = "https://us2.app.sysdig.com"
	}

	client := sysdig.NewClient(apiURL, apiToken)

	// Get pipeline results first
	fmt.Println("=== Getting Pipeline Results ===")
	results, err := client.ListPipelineResultsWithDays(1)
	if err != nil {
		log.Printf("Pipeline error: %v", err)
		return
	}

	if len(results) > 0 {
		// Find a result with critical/high vulnerabilities
		var targetResult *sysdig.ScanResult
		for _, result := range results {
			if result.VulnTotalBySeverity.Critical > 0 || result.VulnTotalBySeverity.High > 0 {
				targetResult = &result
				break
			}
		}

		if targetResult != nil {
			fmt.Printf("Testing with result ID: %s\n", targetResult.ResultID)
			fmt.Printf("Original v1 counts - Critical: %d, High: %d, Medium: %d, Low: %d\n",
				targetResult.VulnTotalBySeverity.Critical,
				targetResult.VulnTotalBySeverity.High,
				targetResult.VulnTotalBySeverity.Medium,
				targetResult.VulnTotalBySeverity.Low)

			// Test v1beta1 endpoint
			fmt.Printf("\n=== Testing V1Beta1 Endpoint ===\n")
			detailsV1Beta1, err := client.GetScanResultDetailsV1Beta1(targetResult.ResultID)
			if err != nil {
				log.Printf("GetScanResultDetailsV1Beta1 error: %v", err)

				// Try v1 as fallback
				fmt.Printf("\n=== Fallback to V1 Endpoint ===\n")
				detailsV1, err := client.GetScanResultDetails(targetResult.ResultID)
				if err != nil {
					log.Printf("GetScanResultDetails V1 error: %v", err)
					return
				}
				fmt.Printf("V1 endpoint worked - vulnerabilities count: %d\n", len(detailsV1.Vulnerabilities))
				return
			}

			fmt.Printf("✅ V1Beta1 endpoint successful!\n")
			fmt.Printf("Vulnerabilities count: %d\n", len(detailsV1Beta1.Vulnerabilities))

			// Check if we have fixableVulnTotalBySeverity
			fmt.Printf("\n=== Vulnerability Totals Comparison ===\n")
			fmt.Printf("VulnTotalBySeverity - Critical: %d, High: %d, Medium: %d, Low: %d\n",
				detailsV1Beta1.VulnTotalBySeverity.Critical,
				detailsV1Beta1.VulnTotalBySeverity.High,
				detailsV1Beta1.VulnTotalBySeverity.Medium,
				detailsV1Beta1.VulnTotalBySeverity.Low)

			fmt.Printf("FixableVulnTotalBySeverity - Critical: %d, High: %d, Medium: %d, Low: %d\n",
				detailsV1Beta1.FixableVulnTotalBySeverity.Critical,
				detailsV1Beta1.FixableVulnTotalBySeverity.High,
				detailsV1Beta1.FixableVulnTotalBySeverity.Medium,
				detailsV1Beta1.FixableVulnTotalBySeverity.Low)

			fmt.Printf("ExploitableVulnTotalBySeverity - Critical: %d, High: %d, Medium: %d, Low: %d\n",
				detailsV1Beta1.ExploitableVulnTotalBySeverity.Critical,
				detailsV1Beta1.ExploitableVulnTotalBySeverity.High,
				detailsV1Beta1.ExploitableVulnTotalBySeverity.Medium,
				detailsV1Beta1.ExploitableVulnTotalBySeverity.Low)

			// Show sample vulnerability details
			if len(detailsV1Beta1.Vulnerabilities) > 0 {
				fmt.Printf("\n=== Sample V1Beta1 Vulnerability Details ===\n")
				count := 0
				for vulnID, vuln := range detailsV1Beta1.Vulnerabilities {
					if count >= 3 {
						break
					}

					fmt.Printf("\nVuln %d:\n", count+1)
					fmt.Printf("  ID: %s\n", vulnID)
					fmt.Printf("  Name: %s\n", vuln.Name)
					fmt.Printf("  Severity: %s\n", vuln.Severity)
					fmt.Printf("  Fixable: %t\n", vuln.Fixable)
					fmt.Printf("  Exploitable: %t\n", vuln.Exploitable)
					fmt.Printf("  FixedVersion: %s\n", vuln.FixedVersion)
					fmt.Printf("  CVSS: %.1f\n", vuln.CVSS)

					count++
				}
			}

			// Show raw response structure
			fmt.Printf("\n=== Raw Response Structure ===\n")
			jsonData, _ := json.MarshalIndent(detailsV1Beta1, "", "  ")
			// Show first 1000 chars to avoid overwhelming output
			if len(jsonData) > 1000 {
				fmt.Printf("%s... (truncated)\n", string(jsonData[:1000]))
			} else {
				fmt.Printf("%s\n", string(jsonData))
			}
		}
	}
}