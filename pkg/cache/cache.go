package cache

import (
	"database/sql"
	"fmt"
	"os"
	pathpkg "path/filepath"
	"strings"
	"time"

	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/sysdig"
	_ "github.com/mattn/go-sqlite3"
)

// CacheType represents the type of cache storage
type CacheType string

const (
	CacheTypeSQLite CacheType = "sqlite"
	CacheTypeCSV    CacheType = "csv"
)

// Cache interface for vulnerability caching
type Cache interface {
	Save(vulnerabilities []sysdig.Vulnerability) error
	Load() ([]sysdig.Vulnerability, error)
	Clear() error
	Close() error
}

// ScanResultCache interface for scan result caching with detailed vulnerability info
type ScanResultCache interface {
	SaveScanResults(scanType string, results []sysdig.ScanResult, vulnerabilities map[string][]sysdig.Vulnerability) error
	LoadScanResults(scanType string, days int) ([]ScanResultWithDetails, error)
	ClearScanResults(scanType string) error
	Close() error
}

// ScanResultWithDetails combines scan result with its detailed vulnerability info
type ScanResultWithDetails struct {
	ScanResult      sysdig.ScanResult
	Vulnerabilities []sysdig.Vulnerability
}

// SQLiteCache implements Cache interface using SQLite
type SQLiteCache struct {
	db       *sql.DB
	filepath string
}

// CSVCache is deprecated - SQLite only
type CSVCache struct {
	filepath string
}

// NewCache creates a new cache instance based on the type
func NewCache(cacheType CacheType, filepath string) (Cache, error) {
	switch cacheType {
	case CacheTypeSQLite:
		return NewSQLiteCache(filepath)
	case CacheTypeCSV:
		return NewCSVCache(filepath), nil
	default:
		return nil, fmt.Errorf("unsupported cache type: %s", cacheType)
	}
}

// NewSQLiteCache creates a new SQLite cache
func NewSQLiteCache(filepath string) (*SQLiteCache, error) {
	// Create directory if it doesn't exist
	dir := pathpkg.Dir(filepath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Open or create database
	db, err := sql.Open("sqlite3", filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	cache := &SQLiteCache{
		db:       db,
		filepath: filepath,
	}

	// Create tables
	if err := cache.createTables(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return cache, nil
}

// createTables creates the necessary database tables
func (c *SQLiteCache) createTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS vulnerabilities (
			id TEXT PRIMARY KEY,
			cve TEXT,
			severity TEXT,
			status TEXT,
			description TEXT,
			score REAL,
			vector TEXT,
			published_at TEXT,
			updated_at TEXT,
			fixable BOOLEAN,
			exploitable BOOLEAN,
			fixed_version TEXT,
			metadata TEXT,
			cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS vulnerability_packages (
			vuln_id TEXT,
			package_name TEXT,
			FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
		)`,
		`CREATE TABLE IF NOT EXISTS scan_results (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			result_id TEXT UNIQUE NOT NULL,
			scan_type TEXT NOT NULL,
			created_at TEXT,
			pull_string TEXT,
			asset_type TEXT,
			aws_account_id TEXT,
			aws_account_name TEXT,
			aws_region TEXT,
			workload_type TEXT,
			workload_name TEXT,
			cluster_name TEXT,
			container_name TEXT,
			container_image TEXT,
			critical_count INTEGER DEFAULT 0,
			high_count INTEGER DEFAULT 0,
			medium_count INTEGER DEFAULT 0,
			low_count INTEGER DEFAULT 0,
			total_count INTEGER DEFAULT 0,
			cached_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS scan_vulnerabilities (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			result_id TEXT NOT NULL,
			vuln_id TEXT NOT NULL,
			vuln_name TEXT,
			severity TEXT,
			disclosure_date TEXT,
			package_ref TEXT,
			package_name TEXT,
			package_version TEXT,
			package_type TEXT,
			package_path TEXT,
			fixable BOOLEAN DEFAULT 0,
			exploitable BOOLEAN DEFAULT 0,
			fixed_version TEXT,
			cvss_score REAL,
			cvss_version TEXT,
			FOREIGN KEY (result_id) REFERENCES scan_results(result_id)
		)`,
		`CREATE TABLE IF NOT EXISTS detection_sources (
			vuln_id TEXT,
			type TEXT,
			location TEXT,
			cluster_name TEXT,
			namespace TEXT,
			pod_name TEXT,
			FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
		)`,
		`CREATE TABLE IF NOT EXISTS aws_resources (
			vuln_id TEXT,
			account_id TEXT,
			region TEXT,
			resource_type TEXT,
			resource_id TEXT,
			resource_name TEXT,
			instance_id TEXT,
			cluster_arn TEXT,
			function_arn TEXT,
			FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
		)`,
		`CREATE TABLE IF NOT EXISTS container_info (
			vuln_id TEXT PRIMARY KEY,
			image_name TEXT,
			image_tag TEXT,
			image_id TEXT,
			registry TEXT,
			image_digest TEXT,
			FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_severity ON vulnerabilities(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_fixable ON vulnerabilities(fixable)`,
		`CREATE INDEX IF NOT EXISTS idx_exploitable ON vulnerabilities(exploitable)`,
		`CREATE INDEX IF NOT EXISTS idx_aws_account ON aws_resources(account_id)`,
		`CREATE INDEX IF NOT EXISTS idx_resource_type ON aws_resources(resource_type)`,
		`CREATE INDEX IF NOT EXISTS idx_asset_type ON scan_results(asset_type)`,
	}

	for _, query := range queries {
		if _, err := c.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query: %w", err)
		}
	}

	return nil
}

// Save saves vulnerabilities to SQLite database
func (c *SQLiteCache) Save(vulnerabilities []sysdig.Vulnerability) error {
	tx, err := c.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Clear existing data
	if _, err := tx.Exec("DELETE FROM vulnerabilities"); err != nil {
		return fmt.Errorf("failed to clear vulnerabilities: %w", err)
	}

	// Insert vulnerabilities
	for _, vuln := range vulnerabilities {
		// Extract fields from V2 structure
		fixedVersion := ""
		if vuln.FixedInVersion != nil {
			fixedVersion = *vuln.FixedInVersion
		}

		_, err := tx.Exec(`
			INSERT INTO vulnerabilities (
				id, cve, severity, status, description, score, vector,
				published_at, updated_at, fixable, exploitable, fixed_version, metadata
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			vuln.ID, vuln.Vuln.Name, vuln.Vuln.SeverityString(), "", "",
			vuln.Vuln.CvssScore, "", vuln.Vuln.DisclosureDate, "",
			vuln.Vuln.Fixable, vuln.Vuln.Exploitable, fixedVersion, "",
		)
		if err != nil {
			return fmt.Errorf("failed to insert vulnerability: %w", err)
		}

		// Insert package information
		_, err = tx.Exec(`
			INSERT INTO vulnerability_packages (vuln_id, package_name)
			VALUES (?, ?)`, vuln.ID, vuln.Package.Name)
		if err != nil {
			return fmt.Errorf("failed to insert package: %w", err)
		}

		// V2 API doesn't have detection sources, AWS resources, or container info at the vulnerability level
		// These would be part of the scan result context instead
	}

	return tx.Commit()
}

// Load loads vulnerabilities from SQLite database
func (c *SQLiteCache) Load() ([]sysdig.Vulnerability, error) {
	// Query vulnerabilities
	rows, err := c.db.Query(`
		SELECT v.id, v.cve, v.severity, v.description, v.score, v.published_at,
		       v.fixable, v.exploitable, v.fixed_version, p.package_name
		FROM vulnerabilities v
		LEFT JOIN vulnerability_packages p ON v.id = p.vuln_id
		ORDER BY v.severity DESC, v.score DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerabilities: %w", err)
	}
	defer rows.Close()

	vulnerabilities := []sysdig.Vulnerability{}
	vulnMap := make(map[string]*sysdig.Vulnerability)

	for rows.Next() {
		var vuln sysdig.Vulnerability
		var cve, severityStr, description, publishedAt, fixedVersion, packageName string
		var score float64
		var fixable, exploitable bool

		err := rows.Scan(
			&vuln.ID, &cve, &severityStr, &description, &score, &publishedAt,
			&fixable, &exploitable, &fixedVersion, &packageName,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability: %w", err)
		}

		// Check if we've already created this vulnerability
		if existing, exists := vulnMap[vuln.ID]; exists {
			vuln = *existing
		} else {
			// Create V2 structure
			vuln.Vuln = sysdig.VulnV2{
				Name:           cve,
				CvssScore:      score,
				DisclosureDate: publishedAt,
				Fixable:        fixable,
				Exploitable:    exploitable,
			}

			// Set severity from string
			switch severityStr {
			case "low":
				vuln.Vuln.Severity = 1
			case "medium":
				vuln.Vuln.Severity = 2
			case "high":
				vuln.Vuln.Severity = 3
			case "critical":
				vuln.Vuln.Severity = 4
			}

			if fixedVersion != "" {
				vuln.FixedInVersion = &fixedVersion
			}

			vulnerabilities = append(vulnerabilities, vuln)
			vulnMap[vuln.ID] = &vulnerabilities[len(vulnerabilities)-1]
		}

		// Set package information if available
		if packageName != "" {
			vulnMap[vuln.ID].Package.Name = packageName
		}
	}

	return vulnerabilities, nil
}

// Clear clears the cache
func (c *SQLiteCache) Clear() error {
	_, err := c.db.Exec("DELETE FROM vulnerabilities")
	return err
}

// Close closes the database connection
func (c *SQLiteCache) Close() error {
	return c.db.Close()
}

// NewCSVCache creates a new CSV cache
func NewCSVCache(filepath string) *CSVCache {
	return &CSVCache{filepath: filepath}
}

// Save - CSV is deprecated, use SQLite
func (c *CSVCache) Save(vulnerabilities []sysdig.Vulnerability) error {
	return fmt.Errorf("CSV cache is deprecated, use SQLite cache instead")
}

// Load - CSV is deprecated, use SQLite
func (c *CSVCache) Load() ([]sysdig.Vulnerability, error) {
	return nil, fmt.Errorf("CSV cache is deprecated, use SQLite cache instead")
}

// Clear clears the cache by removing the CSV file
func (c *CSVCache) Clear() error {
	return os.Remove(c.filepath)
}

// Close does nothing for CSV cache
func (c *CSVCache) Close() error {
	return nil
}

// NewScanResultCache creates a new SQLite-based scan result cache
func NewScanResultCache(filepath string) (ScanResultCache, error) {
	cache, err := NewSQLiteCache(filepath)
	if err != nil {
		return nil, err
	}
	return cache, nil
}

// SaveScanResults implements ScanResultCache interface for SQLiteCache - V2 API only
func (c *SQLiteCache) SaveScanResults(scanType string, results []sysdig.ScanResult, vulnerabilities map[string][]sysdig.Vulnerability) error {
	tx, err := c.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Prepare statements
	insertScanResult, err := tx.Prepare(`
		INSERT OR REPLACE INTO scan_results
		(result_id, scan_type, created_at, pull_string, asset_type, aws_account_id, aws_account_name,
		 aws_region, workload_type, workload_name, cluster_name, container_name,
		 container_image, critical_count, high_count, medium_count, low_count, total_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("failed to prepare scan result statement: %w", err)
	}
	defer insertScanResult.Close()

	insertVuln, err := tx.Prepare(`
		INSERT OR REPLACE INTO scan_vulnerabilities
		(result_id, vuln_id, vuln_name, severity, disclosure_date, package_ref, package_name, package_version, package_type, package_path, fixable, exploitable, fixed_version, cvss_score, cvss_version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("failed to prepare vulnerability statement: %w", err)
	}
	defer insertVuln.Close()

	// Process each scan result
	for _, result := range results {
		// Extract AWS and workload information from scope
		awsAccountID := extractStringFromScope(result.Scope, "aws.account.id")
		awsAccountName := extractStringFromScope(result.Scope, "aws.account.name")
		awsRegion := extractStringFromScope(result.Scope, "aws.region")

		var workloadType, workloadName, clusterName, containerName string
		if extractStringFromScope(result.Scope, "aws.ecs.cluster.name") != "" {
			workloadType = "ecs"
			clusterName = extractStringFromScope(result.Scope, "aws.ecs.cluster.name")
			containerName = extractStringFromScope(result.Scope, "aws.ecs.task.container.name")
			workloadName = fmt.Sprintf("%s/%s", clusterName, containerName)
		} else if extractStringFromScope(result.Scope, "aws.lambda.name") != "" {
			workloadType = "lambda"
			workloadName = extractStringFromScope(result.Scope, "aws.lambda.name")
		} else if extractStringFromScope(result.Scope, "host.hostName") != "" {
			workloadType = "host"
			workloadName = extractStringFromScope(result.Scope, "host.hostName")
		}

		containerImage := extractStringFromScope(result.Scope, "aws.ecs.task.container.image")
		totalCount := result.VulnTotalBySeverity.Critical + result.VulnTotalBySeverity.High +
			result.VulnTotalBySeverity.Medium + result.VulnTotalBySeverity.Low

		// Extract asset type from scope
		assetType := extractStringFromScope(result.Scope, "asset.type")

		// Handle created_at: use NULL if empty
		var createdAtValue interface{}
		if result.CreatedAt == "" {
			createdAtValue = nil
		} else {
			createdAtValue = result.CreatedAt
		}

		// Insert scan result
		_, err = insertScanResult.Exec(
			result.ResultID, scanType, createdAtValue, result.PullString, assetType,
			awsAccountID, awsAccountName, awsRegion, workloadType, workloadName,
			clusterName, containerName, containerImage,
			result.VulnTotalBySeverity.Critical, result.VulnTotalBySeverity.High,
			result.VulnTotalBySeverity.Medium, result.VulnTotalBySeverity.Low, totalCount)
		if err != nil {
			return fmt.Errorf("failed to insert scan result: %w", err)
		}

		// Insert V2 vulnerabilities if available
		if vulnList, exists := vulnerabilities[result.ResultID]; exists {
			for _, vuln := range vulnList {
				// V2 API uses proper fixable logic based on fixedInVersion
				fixedVersion := ""
				fixable := vuln.Vuln.Fixable
				if vuln.FixedInVersion != nil {
					fixedVersion = *vuln.FixedInVersion
					fixable = true
				}

				_, err = insertVuln.Exec(
					result.ResultID, vuln.ID, vuln.Vuln.Name, vuln.Vuln.SeverityString(),
					vuln.Vuln.DisclosureDate, vuln.Package.ID, vuln.Package.Name, vuln.Package.Version, vuln.Package.Type, "",
					fixable, vuln.Vuln.Exploitable, fixedVersion, vuln.Vuln.CvssScore, vuln.Vuln.CvssVersion)
				if err != nil {
					return fmt.Errorf("failed to insert vulnerability: %w", err)
				}
			}
		}
	}

	return tx.Commit()
}

// LoadScanResults implements ScanResultCache interface for SQLiteCache
func (c *SQLiteCache) LoadScanResults(scanType string, days int) ([]ScanResultWithDetails, error) {
	// Calculate cutoff date
	cutoffDate := time.Now().AddDate(0, 0, -days).Format(time.RFC3339)

	// Load scan results
	query := `
		SELECT result_id, scan_type, created_at, pull_string, asset_type,
		       aws_account_id, aws_account_name, aws_region,
		       workload_type, workload_name, cluster_name,
		       container_name, container_image,
		       critical_count, high_count, medium_count, low_count, total_count
		FROM scan_results
		WHERE scan_type = ? AND (created_at >= ? OR created_at IS NULL)
		ORDER BY created_at DESC
	`

	rows, err := c.db.Query(query, scanType, cutoffDate)
	if err != nil {
		return nil, fmt.Errorf("failed to query scan results: %w", err)
	}
	defer rows.Close()

	results := []ScanResultWithDetails{}

	for rows.Next() {
		var r ScanResultWithDetails
		var createdAt, pullString, assetType sql.NullString
		var awsAccountID, awsAccountName, awsRegion sql.NullString
		var workloadType, workloadName, clusterName sql.NullString
		var containerName, containerImage sql.NullString

		err := rows.Scan(
			&r.ScanResult.ResultID,
			&scanType, // scan_type (already filtered by WHERE clause)
			&createdAt,
			&pullString,
			&assetType,
			&awsAccountID,
			&awsAccountName,
			&awsRegion,
			&workloadType,
			&workloadName,
			&clusterName,
			&containerName,
			&containerImage,
			&r.ScanResult.VulnTotalBySeverity.Critical,
			&r.ScanResult.VulnTotalBySeverity.High,
			&r.ScanResult.VulnTotalBySeverity.Medium,
			&r.ScanResult.VulnTotalBySeverity.Low,
			&r.ScanResult.VulnTotalBySeverity.Negligible,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Set nullable fields
		if createdAt.Valid {
			r.ScanResult.CreatedAt = createdAt.String
		}
		if pullString.Valid {
			r.ScanResult.PullString = pullString.String
			r.ScanResult.MainAssetName = pullString.String // For pipeline, use pullString as asset name
		}

		// Build Scope map for runtime results
		if scanType == "runtime" {
			r.ScanResult.Scope = make(map[string]interface{})
			if assetType.Valid {
				r.ScanResult.Scope["asset.type"] = assetType.String
			}
			if awsAccountID.Valid && awsAccountID.String != "" {
				r.ScanResult.Scope["aws.accountId"] = awsAccountID.String
			}
			if awsRegion.Valid && awsRegion.String != "" {
				r.ScanResult.Scope["aws.region"] = awsRegion.String
			}
			if clusterName.Valid && clusterName.String != "" {
				r.ScanResult.Scope["kubernetes.cluster.name"] = clusterName.String
			}
			if workloadType.Valid && workloadType.String != "" {
				r.ScanResult.Scope["kubernetes.workload.type"] = workloadType.String
			}
			if workloadName.Valid && workloadName.String != "" {
				r.ScanResult.Scope["kubernetes.workload.name"] = workloadName.String
			}
			if containerName.Valid && containerName.String != "" {
				r.ScanResult.Scope["container.name"] = containerName.String
			}
			if containerImage.Valid && containerImage.String != "" {
				r.ScanResult.Scope["container.image"] = containerImage.String
			}
			// Use workload name or container name as MainAssetName
			if workloadName.Valid {
				r.ScanResult.MainAssetName = workloadName.String
			} else if containerName.Valid {
				r.ScanResult.MainAssetName = containerName.String
			}
		}

		// Load vulnerabilities for this result
		vulnQuery := `
			SELECT vuln_id, vuln_name, severity, disclosure_date,
			       package_ref, package_name, package_version, package_type, package_path,
			       fixable, exploitable, cvss_score, cvss_version
			FROM scan_vulnerabilities
			WHERE result_id = ?
		`
		vulnRows, err := c.db.Query(vulnQuery, r.ScanResult.ResultID)
		if err != nil {
			return nil, fmt.Errorf("failed to query vulnerabilities for result %s: %w", r.ScanResult.ResultID, err)
		}

		vulnerabilities := []sysdig.Vulnerability{}
		for vulnRows.Next() {
			var vuln sysdig.Vulnerability
			var disclosureDate, packagePath sql.NullString
			var cvssVersion sql.NullString
			var cvssScore sql.NullFloat64
			var severityStr string

			err := vulnRows.Scan(
				&vuln.ID,
				&vuln.Vuln.Name,
				&severityStr,
				&disclosureDate,
				&vuln.Package.ID,
				&vuln.Package.Name,
				&vuln.Package.Version,
				&vuln.Package.Type,
				&packagePath,
				&vuln.Vuln.Fixable,
				&vuln.Vuln.Exploitable,
				&cvssScore,
				&cvssVersion,
			)
			if err != nil {
				vulnRows.Close()
				return nil, fmt.Errorf("failed to scan vulnerability row: %w", err)
			}

			// Convert severity string to int
			vuln.Vuln.Severity = severityStringToInt(severityStr)

			if disclosureDate.Valid {
				vuln.Vuln.DisclosureDate = disclosureDate.String
			}
			if cvssScore.Valid {
				vuln.Vuln.CvssScore = cvssScore.Float64
			}
			if cvssVersion.Valid {
				vuln.Vuln.CvssVersion = cvssVersion.String
			}

			vulnerabilities = append(vulnerabilities, vuln)
		}
		vulnRows.Close()

		r.Vulnerabilities = vulnerabilities
		results = append(results, r)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return results, nil
}

// severityStringToInt converts severity string to integer value
func severityStringToInt(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	case "negligible":
		return 5
	default:
		return 0
	}
}

// ClearScanResults implements ScanResultCache interface for SQLiteCache
func (c *SQLiteCache) ClearScanResults(scanType string) error {
	_, err := c.db.Exec("DELETE FROM scan_vulnerabilities WHERE result_id IN (SELECT result_id FROM scan_results WHERE scan_type = ?)", scanType)
	if err != nil {
		return fmt.Errorf("failed to clear scan vulnerabilities: %w", err)
	}

	_, err = c.db.Exec("DELETE FROM scan_results WHERE scan_type = ?", scanType)
	if err != nil {
		return fmt.Errorf("failed to clear scan results: %w", err)
	}

	return nil
}

// Helper function to extract string values from scope map
func extractStringFromScope(scope map[string]interface{}, key string) string {
	if value, exists := scope[key]; exists {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}
