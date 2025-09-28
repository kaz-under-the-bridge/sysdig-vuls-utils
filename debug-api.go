package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/sysdig"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

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

	// Test pipeline results with pagination
	fmt.Println("=== Testing Pipeline Results API with Pagination ===")
	results, err := client.ListPipelineResults()
	if err != nil {
		log.Printf("Pipeline error: %v", err)
	} else {
		fmt.Printf("Pipeline results count: %d\n", len(results))
		fmt.Printf("Testing pagination - if count > 1000, pagination is working!\n")
		if len(results) > 0 {
			// Show first few result IDs
			fmt.Printf("First 5 result IDs:\n")
			for i, result := range results {
				if i >= 5 {
					break
				}
				fmt.Printf("  %d: %s\n", i+1, result.ResultID)
			}

			// Test GetScanResultDetails with first result ID
			fmt.Printf("\nTesting GetScanResultDetails with first result ID: %s\n", results[0].ResultID)
			details, err := client.GetScanResultDetails(results[0].ResultID)
			if err != nil {
				log.Printf("GetScanResultDetails error: %v", err)
			} else {
				fmt.Printf("Scan details retrieved successfully! Vulnerability count: %d\n", len(details.Vulnerabilities))
			}
		}
	}

	fmt.Println("\n=== Testing Runtime Results API ===")
	runtimeResults, err := client.ListRuntimeResults()
	if err != nil {
		log.Printf("Runtime error: %v", err)
	} else {
		fmt.Printf("Runtime results count: %d\n", len(runtimeResults))
		if len(runtimeResults) > 0 {
			// Show first result in detail
			jsonData, _ := json.MarshalIndent(runtimeResults[0], "", "  ")
			fmt.Printf("First runtime result:\n%s\n", jsonData)
		}
	}
}