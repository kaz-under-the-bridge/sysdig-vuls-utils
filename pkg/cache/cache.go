package cache

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	pathpkg "path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/sysdig"
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

// SQLiteCache implements Cache interface using SQLite
type SQLiteCache struct {
	db       *sql.DB
	filepath string
}

// CSVCache implements Cache interface using CSV files
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
		metadata, _ := json.Marshal(vuln.Metadata)

		_, err := tx.Exec(`
			INSERT INTO vulnerabilities (
				id, cve, severity, status, description, score, vector,
				published_at, updated_at, fixable, exploitable, fixed_version, metadata
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			vuln.ID, vuln.CVE, vuln.Severity, vuln.Status, vuln.Description,
			vuln.Score, vuln.Vector, vuln.PublishedAt, vuln.UpdatedAt,
			vuln.Fixable, vuln.Exploitable, vuln.FixedVersion, string(metadata),
		)
		if err != nil {
			return fmt.Errorf("failed to insert vulnerability: %w", err)
		}

		// Insert packages
		for _, pkg := range vuln.Packages {
			_, err := tx.Exec(`
				INSERT INTO vulnerability_packages (vuln_id, package_name)
				VALUES (?, ?)`, vuln.ID, pkg)
			if err != nil {
				return fmt.Errorf("failed to insert package: %w", err)
			}
		}

		// Insert detection sources
		for _, source := range vuln.DetectionSources {
			_, err := tx.Exec(`
				INSERT INTO detection_sources (
					vuln_id, type, location, cluster_name, namespace, pod_name
				) VALUES (?, ?, ?, ?, ?, ?)`,
				vuln.ID, source.Type, source.Location, source.ClusterName,
				source.Namespace, source.PodName,
			)
			if err != nil {
				return fmt.Errorf("failed to insert detection source: %w", err)
			}
		}

		// Insert AWS resources
		for _, resource := range vuln.AWSResources {
			_, err := tx.Exec(`
				INSERT INTO aws_resources (
					vuln_id, account_id, region, resource_type, resource_id,
					resource_name, instance_id, cluster_arn, function_arn
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				vuln.ID, resource.AccountID, resource.Region, resource.ResourceType,
				resource.ResourceID, resource.ResourceName, resource.InstanceID,
				resource.ClusterArn, resource.FunctionArn,
			)
			if err != nil {
				return fmt.Errorf("failed to insert AWS resource: %w", err)
			}
		}

		// Insert container info
		if vuln.ContainerInfo != nil {
			_, err := tx.Exec(`
				INSERT INTO container_info (
					vuln_id, image_name, image_tag, image_id, registry, image_digest
				) VALUES (?, ?, ?, ?, ?, ?)`,
				vuln.ID, vuln.ContainerInfo.ImageName, vuln.ContainerInfo.ImageTag,
				vuln.ContainerInfo.ImageID, vuln.ContainerInfo.Registry,
				vuln.ContainerInfo.ImageDigest,
			)
			if err != nil {
				return fmt.Errorf("failed to insert container info: %w", err)
			}
		}
	}

	return tx.Commit()
}

// Load loads vulnerabilities from SQLite database
func (c *SQLiteCache) Load() ([]sysdig.Vulnerability, error) {
	// Query vulnerabilities
	rows, err := c.db.Query(`
		SELECT id, cve, severity, status, description, score, vector,
		       published_at, updated_at, fixable, exploitable, fixed_version, metadata
		FROM vulnerabilities
		ORDER BY severity DESC, score DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerabilities: %w", err)
	}
	defer rows.Close()

	vulnerabilities := []sysdig.Vulnerability{}
	vulnMap := make(map[string]*sysdig.Vulnerability)

	for rows.Next() {
		var vuln sysdig.Vulnerability
		var metadataStr string

		err := rows.Scan(
			&vuln.ID, &vuln.CVE, &vuln.Severity, &vuln.Status, &vuln.Description,
			&vuln.Score, &vuln.Vector, &vuln.PublishedAt, &vuln.UpdatedAt,
			&vuln.Fixable, &vuln.Exploitable, &vuln.FixedVersion, &metadataStr,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability: %w", err)
		}

		if metadataStr != "" {
			json.Unmarshal([]byte(metadataStr), &vuln.Metadata)
		}

		vulnerabilities = append(vulnerabilities, vuln)
		vulnMap[vuln.ID] = &vulnerabilities[len(vulnerabilities)-1]
	}

	// Load packages
	pkgRows, err := c.db.Query("SELECT vuln_id, package_name FROM vulnerability_packages")
	if err != nil {
		return nil, fmt.Errorf("failed to query packages: %w", err)
	}
	defer pkgRows.Close()

	for pkgRows.Next() {
		var vulnID, pkgName string
		if err := pkgRows.Scan(&vulnID, &pkgName); err != nil {
			continue
		}
		if vuln, ok := vulnMap[vulnID]; ok {
			vuln.Packages = append(vuln.Packages, pkgName)
		}
	}

	// Load detection sources
	srcRows, err := c.db.Query(`
		SELECT vuln_id, type, location, cluster_name, namespace, pod_name
		FROM detection_sources
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query detection sources: %w", err)
	}
	defer srcRows.Close()

	for srcRows.Next() {
		var vulnID string
		var src sysdig.DetectionSource
		if err := srcRows.Scan(&vulnID, &src.Type, &src.Location,
			&src.ClusterName, &src.Namespace, &src.PodName); err != nil {
			continue
		}
		if vuln, ok := vulnMap[vulnID]; ok {
			vuln.DetectionSources = append(vuln.DetectionSources, src)
		}
	}

	// Load AWS resources
	awsRows, err := c.db.Query(`
		SELECT vuln_id, account_id, region, resource_type, resource_id,
		       resource_name, instance_id, cluster_arn, function_arn
		FROM aws_resources
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query AWS resources: %w", err)
	}
	defer awsRows.Close()

	for awsRows.Next() {
		var vulnID string
		var res sysdig.AWSResource
		if err := awsRows.Scan(&vulnID, &res.AccountID, &res.Region, &res.ResourceType,
			&res.ResourceID, &res.ResourceName, &res.InstanceID,
			&res.ClusterArn, &res.FunctionArn); err != nil {
			continue
		}
		if vuln, ok := vulnMap[vulnID]; ok {
			vuln.AWSResources = append(vuln.AWSResources, res)
		}
	}

	// Load container info
	containerRows, err := c.db.Query(`
		SELECT vuln_id, image_name, image_tag, image_id, registry, image_digest
		FROM container_info
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query container info: %w", err)
	}
	defer containerRows.Close()

	for containerRows.Next() {
		var vulnID string
		var info sysdig.ContainerInfo
		if err := containerRows.Scan(&vulnID, &info.ImageName, &info.ImageTag,
			&info.ImageID, &info.Registry, &info.ImageDigest); err != nil {
			continue
		}
		if vuln, ok := vulnMap[vulnID]; ok {
			vuln.ContainerInfo = &info
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

// Save saves vulnerabilities to CSV file
func (c *CSVCache) Save(vulnerabilities []sysdig.Vulnerability) error {
	// Create directory if it doesn't exist
	dir := pathpkg.Dir(c.filepath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Create CSV file
	file, err := os.Create(c.filepath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"ID", "CVE", "Severity", "Status", "Description", "Score", "Vector",
		"PublishedAt", "UpdatedAt", "Fixable", "Exploitable", "FixedVersion",
		"Packages", "DetectionSources", "AWSAccounts", "AWSResourceTypes",
		"ContainerImage", "ContainerTag", "CachedAt",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write data
	for _, vuln := range vulnerabilities {
		// Prepare complex fields
		packages := strings.Join(vuln.Packages, ";")

		detectionSources := []string{}
		for _, src := range vuln.DetectionSources {
			detectionSources = append(detectionSources,
				fmt.Sprintf("%s:%s", src.Type, src.Location))
		}

		awsAccounts := []string{}
		awsResourceTypes := []string{}
		accountMap := make(map[string]bool)
		resourceTypeMap := make(map[string]bool)

		for _, res := range vuln.AWSResources {
			accountMap[res.AccountID] = true
			resourceTypeMap[res.ResourceType] = true
		}

		for account := range accountMap {
			awsAccounts = append(awsAccounts, account)
		}
		for resType := range resourceTypeMap {
			awsResourceTypes = append(awsResourceTypes, resType)
		}

		containerImage := ""
		containerTag := ""
		if vuln.ContainerInfo != nil {
			containerImage = vuln.ContainerInfo.ImageName
			containerTag = vuln.ContainerInfo.ImageTag
		}

		record := []string{
			vuln.ID,
			vuln.CVE,
			vuln.Severity,
			vuln.Status,
			vuln.Description,
			fmt.Sprintf("%.2f", vuln.Score),
			vuln.Vector,
			vuln.PublishedAt,
			vuln.UpdatedAt,
			fmt.Sprintf("%t", vuln.Fixable),
			fmt.Sprintf("%t", vuln.Exploitable),
			vuln.FixedVersion,
			packages,
			strings.Join(detectionSources, ";"),
			strings.Join(awsAccounts, ";"),
			strings.Join(awsResourceTypes, ";"),
			containerImage,
			containerTag,
			time.Now().Format(time.RFC3339),
		}

		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write record: %w", err)
		}
	}

	return nil
}

// Load loads vulnerabilities from CSV file
func (c *CSVCache) Load() ([]sysdig.Vulnerability, error) {
	file, err := os.Open(c.filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return []sysdig.Vulnerability{}, nil
		}
		return nil, fmt.Errorf("failed to open CSV file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)

	// Read header
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	// Create header index map
	headerMap := make(map[string]int)
	for i, h := range header {
		headerMap[h] = i
	}

	vulnerabilities := []sysdig.Vulnerability{}

	// Read records
	for {
		record, err := reader.Read()
		if err != nil {
			break
		}

		vuln := sysdig.Vulnerability{
			ID:           record[headerMap["ID"]],
			CVE:          record[headerMap["CVE"]],
			Severity:     record[headerMap["Severity"]],
			Status:       record[headerMap["Status"]],
			Description:  record[headerMap["Description"]],
			Vector:       record[headerMap["Vector"]],
			PublishedAt:  record[headerMap["PublishedAt"]],
			UpdatedAt:    record[headerMap["UpdatedAt"]],
			FixedVersion: record[headerMap["FixedVersion"]],
		}

		// Parse score
		fmt.Sscanf(record[headerMap["Score"]], "%f", &vuln.Score)

		// Parse boolean fields
		vuln.Fixable = record[headerMap["Fixable"]] == "true"
		vuln.Exploitable = record[headerMap["Exploitable"]] == "true"

		// Parse packages
		if packages := record[headerMap["Packages"]]; packages != "" {
			vuln.Packages = strings.Split(packages, ";")
		}

		// Parse detection sources
		if sources := record[headerMap["DetectionSources"]]; sources != "" {
			for _, src := range strings.Split(sources, ";") {
				parts := strings.Split(src, ":")
				if len(parts) >= 2 {
					vuln.DetectionSources = append(vuln.DetectionSources, sysdig.DetectionSource{
						Type:     parts[0],
						Location: parts[1],
					})
				}
			}
		}

		// Parse AWS resources (simplified)
		if accounts := record[headerMap["AWSAccounts"]]; accounts != "" {
			for _, account := range strings.Split(accounts, ";") {
				if account != "" {
					vuln.AWSResources = append(vuln.AWSResources, sysdig.AWSResource{
						AccountID: account,
					})
				}
			}
		}

		// Parse container info
		if image := record[headerMap["ContainerImage"]]; image != "" {
			vuln.ContainerInfo = &sysdig.ContainerInfo{
				ImageName: image,
				ImageTag:  record[headerMap["ContainerTag"]],
			}
		}

		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities, nil
}

// Clear clears the cache by removing the CSV file
func (c *CSVCache) Clear() error {
	return os.Remove(c.filepath)
}

// Close does nothing for CSV cache
func (c *CSVCache) Close() error {
	return nil
}