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

	// First, get pipeline results to get a valid result ID
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
			fmt.Printf("Testing V2 API with result ID: %s\n", targetResult.ResultID)
			fmt.Printf("Original counts - Critical: %d, High: %d\n",
				targetResult.VulnTotalBySeverity.Critical,
				targetResult.VulnTotalBySeverity.High)

			// Test v2 endpoint - first page
			fmt.Printf("\n=== Testing V2 Endpoint (First Page) ===\n")
			vulnPackagesV2, err := client.GetVulnPackagesV2(targetResult.ResultID, 20, 0, "vulnSeverity", "desc")
			if err != nil {
				log.Printf("GetVulnPackagesV2 error: %v", err)
				return
			}

			fmt.Printf("✅ V2 endpoint successful!\n")
			fmt.Printf("Page info: Returned: %d, Offset: %d, Total Matched: %d\n",
				vulnPackagesV2.Page.Returned,
				vulnPackagesV2.Page.Offset,
				vulnPackagesV2.Page.Matched)

			// Show sample vulnerability details with new fields
			if len(vulnPackagesV2.Data) > 0 {
				fmt.Printf("\n=== Sample V2 Vulnerability Details ===\n")
				for i, vulnPkg := range vulnPackagesV2.Data[:min(3, len(vulnPackagesV2.Data))] {
					fmt.Printf("\nVuln %d:\n", i+1)
					fmt.Printf("  CVE: %s\n", vulnPkg.Vuln.Name)
					fmt.Printf("  Severity: %s (%d)\n", vulnPkg.Vuln.SeverityString(), vulnPkg.Vuln.Severity)
					fmt.Printf("  CVSS Score: %.1f\n", vulnPkg.Vuln.CvssScore)
					fmt.Printf("  Exploitable: %t\n", vulnPkg.Vuln.Exploitable)
					fmt.Printf("  CISA KEV: %t\n", vulnPkg.Vuln.CisaKev)
					fmt.Printf("  Package: %s (%s)\n", vulnPkg.Package.Name, vulnPkg.Package.Version)
					fmt.Printf("  Fixed Version: %s\n", vulnPkg.FixedInVersion)

					// EPSS Score if available
					if vulnPkg.Vuln.EpssScore != nil {
						fmt.Printf("  EPSS Score: %.5f (Percentile: %.3f)\n",
							vulnPkg.Vuln.EpssScore.Score,
							vulnPkg.Vuln.EpssScore.Percentile)
					}

					// Provider metadata
					if nvdMeta, ok := vulnPkg.Vuln.ProvidersMetadata["nvd"]; ok {
						if nvdMeta.Severity != nil {
							fmt.Printf("  NVD Severity: %s\n", *nvdMeta.Severity)
						}
					}
				}
			}

			// Test getting all vulnerability packages
			fmt.Printf("\n=== Testing Get All V2 Vulnerabilities ===\n")
			allVulnPackages, err := client.GetAllVulnPackagesV2(targetResult.ResultID)
			if err != nil {
				log.Printf("GetAllVulnPackagesV2 error: %v", err)
				return
			}

			fmt.Printf("✅ Retrieved all vulnerabilities: %d total\n", len(allVulnPackages))

			// Count by severity and exploitable status
			severityCounts := map[string]int{}
			exploitableCount := 0
			cisaKevCount := 0
			fixableCount := 0

			for _, vulnPkg := range allVulnPackages {
				severity := vulnPkg.Vuln.SeverityString()
				severityCounts[severity]++

				if vulnPkg.Vuln.Exploitable {
					exploitableCount++
				}
				if vulnPkg.Vuln.CisaKev {
					cisaKevCount++
				}
				if vulnPkg.FixedInVersion != "" {
					fixableCount++
				}
			}

			fmt.Printf("\n=== V2 Vulnerability Summary ===\n")
			fmt.Printf("Total: %d vulnerabilities\n", len(allVulnPackages))
			fmt.Printf("By Severity:\n")
			for _, sev := range []string{"critical", "high", "medium", "low"} {
				if count, ok := severityCounts[sev]; ok {
					fmt.Printf("  %s: %d\n", sev, count)
				}
			}
			fmt.Printf("Exploitable: %d\n", exploitableCount)
			fmt.Printf("CISA KEV: %d\n", cisaKevCount)
			fmt.Printf("Fixable: %d\n", fixableCount)

			// Show raw response structure for first vulnerability
			fmt.Printf("\n=== Raw V2 Response Structure (First Vuln) ===\n")
			if len(allVulnPackages) > 0 {
				jsonData, _ := json.MarshalIndent(allVulnPackages[0], "", "  ")
				// Show first 1500 chars to avoid overwhelming output
				if len(jsonData) > 1500 {
					fmt.Printf("%s... (truncated)\n", string(jsonData[:1500]))
				} else {
					fmt.Printf("%s\n", string(jsonData))
				}
			}
		} else {
			fmt.Println("No pipeline results with critical/high vulnerabilities found")
		}
	} else {
		fmt.Println("No pipeline results found")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}