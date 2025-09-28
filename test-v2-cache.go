package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
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

	// Create new SQLite database for v2 data
	dbPath := "./v2_vulnerability_cache.db"
	os.Remove(dbPath) // Remove existing DB to start fresh

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create schema for v2 vulnerability data
	schema := `
	CREATE TABLE IF NOT EXISTS scan_results (
		result_id TEXT PRIMARY KEY,
		created_at TEXT,
		pull_string TEXT,
		vuln_count INTEGER,
		critical_count INTEGER,
		high_count INTEGER,
		medium_count INTEGER,
		low_count INTEGER,
		unknown_count INTEGER,
		cached_at TEXT
	);

	CREATE TABLE IF NOT EXISTS vulnerabilities_v2 (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		result_id TEXT NOT NULL,
		vuln_id TEXT,
		vuln_name TEXT,
		severity INTEGER,
		severity_text TEXT,
		cvss_score REAL,
		cvss_version TEXT,
		cvss_vector TEXT,
		epss_score REAL,
		epss_percentile REAL,
		exploitable BOOLEAN DEFAULT 0,
		cisa_kev BOOLEAN DEFAULT 0,
		disclosure_date TEXT,
		package_id TEXT,
		package_name TEXT,
		package_version TEXT,
		package_type TEXT,
		package_running BOOLEAN DEFAULT 0,
		fixed_version TEXT,
		layer_digest TEXT,
		layer_index INTEGER,
		FOREIGN KEY (result_id) REFERENCES scan_results(result_id)
	);

	CREATE INDEX IF NOT EXISTS idx_result_id ON vulnerabilities_v2(result_id);
	CREATE INDEX IF NOT EXISTS idx_severity ON vulnerabilities_v2(severity);
	CREATE INDEX IF NOT EXISTS idx_exploitable ON vulnerabilities_v2(exploitable);
	CREATE INDEX IF NOT EXISTS idx_cisa_kev ON vulnerabilities_v2(cisa_kev);
	CREATE INDEX IF NOT EXISTS idx_package_name ON vulnerabilities_v2(package_name);
	`

	_, err = db.Exec(schema)
	if err != nil {
		log.Fatal("Failed to create schema:", err)
	}

	fmt.Println("=== Getting Pipeline Results ===")
	results, err := client.ListPipelineResultsWithDays(1)
	if err != nil {
		log.Printf("Pipeline error: %v", err)
		return
	}

	// Filter for results with critical/high vulnerabilities
	var targetResults []sysdig.ScanResult
	for _, result := range results {
		if result.VulnTotalBySeverity.Critical > 0 || result.VulnTotalBySeverity.High > 0 {
			targetResults = append(targetResults, result)
			if len(targetResults) >= 3 { // Test with 3 results
				break
			}
		}
	}

	fmt.Printf("Processing %d scan results with critical/high vulnerabilities\n", len(targetResults))

	// Process each scan result
	for _, scanResult := range targetResults {
		fmt.Printf("\nProcessing result: %s\n", scanResult.ResultID)

		// Insert scan result
		_, err = db.Exec(`
			INSERT INTO scan_results (result_id, created_at, pull_string, vuln_count,
				critical_count, high_count, medium_count, low_count, unknown_count, cached_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			scanResult.ResultID,
			scanResult.CreatedAt,
			scanResult.PullString,
			scanResult.VulnTotalBySeverity.Critical + scanResult.VulnTotalBySeverity.High +
				scanResult.VulnTotalBySeverity.Medium + scanResult.VulnTotalBySeverity.Low,
			scanResult.VulnTotalBySeverity.Critical,
			scanResult.VulnTotalBySeverity.High,
			scanResult.VulnTotalBySeverity.Medium,
			scanResult.VulnTotalBySeverity.Low,
			0, // unknown count
			time.Now().Format(time.RFC3339),
		)
		if err != nil {
			log.Printf("Failed to insert scan result: %v", err)
			continue
		}

		// Get vulnerability details using v2 API
		fmt.Printf("  Fetching v2 vulnerability details...")
		vulnPackages, err := client.GetAllVulnPackagesV2(scanResult.ResultID)
		if err != nil {
			log.Printf("Failed to get v2 vulnerabilities: %v", err)
			continue
		}

		fmt.Printf(" Retrieved %d vulnerabilities\n", len(vulnPackages))

		// Insert vulnerabilities
		tx, err := db.Begin()
		if err != nil {
			log.Printf("Failed to begin transaction: %v", err)
			continue
		}

		insertStmt, err := tx.Prepare(`
			INSERT INTO vulnerabilities_v2 (
				result_id, vuln_id, vuln_name, severity, severity_text,
				cvss_score, cvss_version, cvss_vector,
				epss_score, epss_percentile, exploitable, cisa_kev,
				disclosure_date, package_id, package_name, package_version,
				package_type, package_running, fixed_version,
				layer_digest, layer_index
			) VALUES (
				?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
			)`)
		if err != nil {
			log.Printf("Failed to prepare statement: %v", err)
			tx.Rollback()
			continue
		}
		defer insertStmt.Close()

		for _, vulnPkg := range vulnPackages {
			// Extract CVSS vector (from any provider)
			cvssVector := ""
			if nvdMeta, ok := vulnPkg.Vuln.ProvidersMetadata["nvd"]; ok && nvdMeta.CvssScore != nil {
				cvssVector = nvdMeta.CvssScore.Vector
			}

			// Extract EPSS data
			epssScore := 0.0
			epssPercentile := 0.0
			if vulnPkg.Vuln.EpssScore != nil {
				epssScore = vulnPkg.Vuln.EpssScore.Score
				epssPercentile = vulnPkg.Vuln.EpssScore.Percentile
			}

			// Extract layer data
			layerDigest := ""
			layerIndex := 0
			if vulnPkg.Package.Layer != nil {
				layerDigest = vulnPkg.Package.Layer.Digest
				layerIndex = vulnPkg.Package.Layer.Index
			}

			_, err = insertStmt.Exec(
				scanResult.ResultID,
				vulnPkg.ID,
				vulnPkg.Vuln.Name,
				vulnPkg.Vuln.Severity,
				vulnPkg.Vuln.SeverityString(),
				vulnPkg.Vuln.CvssScore,
				vulnPkg.Vuln.CvssVersion,
				cvssVector,
				epssScore,
				epssPercentile,
				vulnPkg.Vuln.Exploitable,
				vulnPkg.Vuln.CisaKev,
				vulnPkg.Vuln.DisclosureDate,
				vulnPkg.Package.ID,
				vulnPkg.Package.Name,
				vulnPkg.Package.Version,
				vulnPkg.Package.Type,
				vulnPkg.Package.Running,
				vulnPkg.FixedInVersion,
				layerDigest,
				layerIndex,
			)
			if err != nil {
				log.Printf("Failed to insert vulnerability: %v", err)
			}
		}

		if err = tx.Commit(); err != nil {
			log.Printf("Failed to commit transaction: %v", err)
			tx.Rollback()
		}
	}

	// Verify cached data
	fmt.Println("\n=== Verification: Cached Data Summary ===")

	// Count total vulnerabilities
	var totalVulns int
	err = db.QueryRow("SELECT COUNT(*) FROM vulnerabilities_v2").Scan(&totalVulns)
	if err == nil {
		fmt.Printf("Total cached vulnerabilities: %d\n", totalVulns)
	}

	// Count by severity
	rows, err := db.Query(`
		SELECT severity_text, COUNT(*) as count
		FROM vulnerabilities_v2
		GROUP BY severity_text
		ORDER BY severity`)
	if err == nil {
		defer rows.Close()
		fmt.Println("\nVulnerabilities by severity:")
		for rows.Next() {
			var severity string
			var count int
			rows.Scan(&severity, &count)
			fmt.Printf("  %s: %d\n", severity, count)
		}
	}

	// Count exploitable and CISA KEV
	var exploitableCount, cisaKevCount, fixableCount int
	db.QueryRow("SELECT COUNT(*) FROM vulnerabilities_v2 WHERE exploitable = 1").Scan(&exploitableCount)
	db.QueryRow("SELECT COUNT(*) FROM vulnerabilities_v2 WHERE cisa_kev = 1").Scan(&cisaKevCount)
	db.QueryRow("SELECT COUNT(*) FROM vulnerabilities_v2 WHERE fixed_version != ''").Scan(&fixableCount)

	fmt.Printf("\nExploitable vulnerabilities: %d\n", exploitableCount)
	fmt.Printf("CISA KEV vulnerabilities: %d\n", cisaKevCount)
	fmt.Printf("Fixable vulnerabilities: %d\n", fixableCount)

	// Show top packages with vulnerabilities
	fmt.Println("\nTop 5 packages with most vulnerabilities:")
	rows, err = db.Query(`
		SELECT package_name, COUNT(*) as vuln_count
		FROM vulnerabilities_v2
		GROUP BY package_name
		ORDER BY vuln_count DESC
		LIMIT 5`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var pkgName string
			var count int
			rows.Scan(&pkgName, &count)
			fmt.Printf("  %s: %d vulnerabilities\n", pkgName, count)
		}
	}

	// Show high EPSS score vulnerabilities
	fmt.Println("\nTop 5 vulnerabilities by EPSS score (exploitability):")
	rows, err = db.Query(`
		SELECT vuln_name, epss_score, epss_percentile, package_name
		FROM vulnerabilities_v2
		WHERE epss_score > 0
		ORDER BY epss_score DESC
		LIMIT 5`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var vulnName, pkgName string
			var epssScore, epssPercentile float64
			rows.Scan(&vulnName, &epssScore, &epssPercentile, &pkgName)
			fmt.Printf("  %s (in %s): EPSS %.4f (percentile %.1f%%)\n",
				vulnName, pkgName, epssScore, epssPercentile*100)
		}
	}

	fmt.Printf("\n✅ Successfully cached v2 vulnerability data to: %s\n", dbPath)
}