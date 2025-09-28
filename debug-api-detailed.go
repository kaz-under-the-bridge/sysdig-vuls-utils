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

	// Get pipeline results
	fmt.Println("=== Getting Pipeline Results ===")
	results, err := client.ListPipelineResultsWithDays(1)
	if err != nil {
		log.Printf("Pipeline error: %v", err)
		return
	}

	if len(results) > 0 {
		// Get detailed results for first result with critical/high vulnerabilities
		var targetResult *sysdig.ScanResult
		for _, result := range results {
			if result.VulnTotalBySeverity.Critical > 0 || result.VulnTotalBySeverity.High > 0 {
				targetResult = &result
				break
			}
		}

		if targetResult != nil {
			fmt.Printf("Testing with result ID: %s\n", targetResult.ResultID)
			details, err := client.GetScanResultDetails(targetResult.ResultID)
			if err != nil {
				log.Printf("GetScanResultDetails error: %v", err)
				return
			}

			fmt.Printf("\n=== Raw API Response Analysis ===\n")

			// Show first vulnerability in detail
			if len(details.Vulnerabilities) > 0 {
				fmt.Printf("Number of vulnerabilities: %d\n", len(details.Vulnerabilities))

				// Print first few vulnerabilities with all available fields
				count := 0
				for vulnID, vuln := range details.Vulnerabilities {
					if count >= 3 {
						break
					}

					fmt.Printf("\n--- Vulnerability %d ---\n", count+1)
					fmt.Printf("VulnID: %s\n", vulnID)

					// Marshal to JSON to see all available fields
					jsonData, _ := json.MarshalIndent(vuln, "", "  ")
					fmt.Printf("Raw JSON data:\n%s\n", jsonData)

					count++
				}
			}

			// Show package info as well
			if len(details.Packages) > 0 {
				fmt.Printf("\n=== Package Info Sample ===\n")
				count := 0
				for pkgID, pkg := range details.Packages {
					if count >= 2 {
						break
					}

					fmt.Printf("PackageID: %s\n", pkgID)
					jsonData, _ := json.MarshalIndent(pkg, "", "  ")
					fmt.Printf("Package JSON:\n%s\n", jsonData)
					count++
				}
			}
		}
	}
}