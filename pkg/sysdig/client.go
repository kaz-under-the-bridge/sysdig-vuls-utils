package sysdig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client represents a Sysdig API client
type Client struct {
	baseURL    string
	apiToken   string
	httpClient *http.Client
}

// Vulnerability represents a vulnerability from Sysdig V2 API
// This is now based on the V2 API structure for consistency
type Vulnerability struct {
	ID             string     `json:"id"`
	Vuln           VulnV2     `json:"vuln"`
	Package        PackageV2  `json:"package"`
	FixedInVersion *string    `json:"fixedInVersion"` // Use pointer to detect null values
}


// VulnerabilityResponse represents the V2 API response for vulnerability lists
type VulnerabilityResponse struct {
	Page PageInfo        `json:"page"`
	Data []Vulnerability `json:"data"`
}

// PageInfo represents pagination information from V2 API
type PageInfo struct {
	Returned int `json:"returned"`
	Offset   int `json:"offset"`
	Matched  int `json:"matched"`
}

type VulnV2 struct {
	Name              string                    `json:"name"`
	Severity          int                       `json:"severity"` // 1=low, 2=medium, 3=high, 4=critical
	CvssVersion       string                    `json:"cvssVersion"`
	CvssScore         float64                   `json:"cvssScore"`
	EpssScore         *EpssScore                `json:"epssScore,omitempty"`
	Exploitable       bool                      `json:"exploitable"`
	CisaKev           bool                      `json:"cisakev"`
	DisclosureDate    string                    `json:"disclosureDate"`
	AcceptedRisks     []interface{}             `json:"acceptedRisks"`
	ProvidersMetadata map[string]ProviderMeta   `json:"providersMetadata"`
	Fixable           bool                      `json:"-"` // Computed based on FixedInVersion
}

type EpssScore struct {
	Score      float64   `json:"score"`
	Percentile float64   `json:"percentile"`
	Timestamp  string    `json:"timestamp"`
}

type ProviderMeta struct {
	PublishDate *string      `json:"publishDate,omitempty"`
	CvssScore   *CvssScore   `json:"cvssScore,omitempty"`
	Severity    *string      `json:"severity,omitempty"`
	EpssScore   *EpssScore   `json:"epssScore,omitempty"`
}

type CvssScore struct {
	Version string  `json:"version"`
	Score   float64 `json:"score"`
	Vector  string  `json:"vector"`
}

type PackageV2 struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Type    string   `json:"type"`
	Running bool     `json:"running"`
	Removed bool     `json:"removed"`
	Layer   *LayerV2 `json:"layer,omitempty"`
}

type LayerV2 struct {
	ID      string `json:"id"`
	Digest  string `json:"digest"`
	Index   int    `json:"index"`
	Command string `json:"command"`
}

// VulnPackageV2 represents the raw V2 API response structure
type VulnPackageV2 struct {
	ID             string     `json:"id"`
	Vuln           VulnV2     `json:"vuln"`
	Package        PackageV2  `json:"package"`
	FixedInVersion string     `json:"fixedInVersion,omitempty"`
}

// VulnPackageResponseV2 represents the V2 API response
type VulnPackageResponseV2 struct {
	Page PageInfo        `json:"page"`
	Data []VulnPackageV2 `json:"data"`
}

// VulnerabilityFilter represents filter options for V2 API
type VulnerabilityFilter struct {
	Severity    []string `json:"severity,omitempty"`    // 1=low, 2=medium, 3=high, 4=critical
	Fixable     *bool    `json:"fixable,omitempty"`
	Exploitable *bool    `json:"exploitable,omitempty"`
	PackageName string   `json:"packageName,omitempty"`
	CVE         string   `json:"cve,omitempty"`
}

// NewClient creates a new Sysdig API client
func NewClient(baseURL, apiToken string) *Client {
	return &Client{
		baseURL:  baseURL,
		apiToken: apiToken,
		httpClient: &http.Client{
			Timeout: 0, // タイムアウト無効化
		},
	}
}

// makeRequest performs an HTTP request to the Sysdig API
func (c *Client) makeRequest(method, endpoint string, body interface{}) (*http.Response, error) {
	var apiURL string
	var url string

	// Handle different endpoint types
	if strings.HasPrefix(endpoint, "/api/") {
		// For v2 scanning endpoints, keep the original base URL (us2.app.sysdig.com)
		apiURL = c.baseURL
		url = fmt.Sprintf("%s%s", apiURL, endpoint)
	} else {
		// For v1 endpoints, use api.us2.sysdig.com instead of us2.app.sysdig.com
		apiURL = strings.Replace(c.baseURL, "us2.app.sysdig.com", "api.us2.sysdig.com", 1)
		// For localhost (mock server), don't change the URL
		if strings.Contains(c.baseURL, "localhost") {
			apiURL = c.baseURL
		}

		if strings.Contains(endpoint, "accepted-risks") {
			url = fmt.Sprintf("%s/secure/vulnerability/v1beta1%s", apiURL, endpoint)
		} else {
			url = fmt.Sprintf("%s/secure/vulnerability/v1%s", apiURL, endpoint)
		}
	}


	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sysdig-vuls-utils/2.0.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

// ListVulnerabilities retrieves all vulnerabilities from a scan result using V2 API
func (c *Client) ListVulnerabilities(resultID string) ([]Vulnerability, error) {
	return c.GetAllVulnPackagesV2(resultID)
}

// GetVulnerability retrieves a specific vulnerability from a scan result by ID using V2 API
func (c *Client) GetVulnerability(resultID, vulnID string) (*Vulnerability, error) {
	allVulns, err := c.GetAllVulnPackagesV2(resultID)
	if err != nil {
		return nil, err
	}

	for _, vuln := range allVulns {
		if vuln.ID == vulnID {
			return &vuln, nil
		}
	}

	return nil, fmt.Errorf("vulnerability not found: %s", vulnID)
}

// UpdateVulnerability is not supported in V2 API - V2 API is read-only

// ListVulnerabilitiesByPackage retrieves vulnerabilities for a specific package
func (c *Client) ListVulnerabilitiesByPackage(packageName string) ([]Vulnerability, error) {
	endpoint := fmt.Sprintf("/vulnerabilities?package=%s", packageName)
	resp, err := c.makeRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var vulnResp VulnerabilityResponse
	if err := json.NewDecoder(resp.Body).Decode(&vulnResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return vulnResp.Data, nil
}

// ListVulnerabilitiesBySeverity retrieves vulnerabilities filtered by severity
func (c *Client) ListVulnerabilitiesBySeverity(severity string) ([]Vulnerability, error) {
	endpoint := fmt.Sprintf("/vulnerabilities?severity=%s", severity)
	resp, err := c.makeRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var vulnResp VulnerabilityResponse
	if err := json.NewDecoder(resp.Body).Decode(&vulnResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return vulnResp.Data, nil
}

// ListVulnerabilitiesWithFilters retrieves vulnerabilities with multiple filters using V2 API
func (c *Client) ListVulnerabilitiesWithFilters(resultID string, filter VulnerabilityFilter) ([]Vulnerability, error) {
	allVulns, err := c.GetAllVulnPackagesV2(resultID)
	if err != nil {
		return nil, err
	}

	var filtered []Vulnerability
	for _, vuln := range allVulns {
		// Apply severity filter
		if len(filter.Severity) > 0 {
			severityMatch := false
			for _, sev := range filter.Severity {
				if vuln.Vuln.SeverityString() == sev {
					severityMatch = true
					break
				}
			}
			if !severityMatch {
				continue
			}
		}

		// Apply fixable filter
		if filter.Fixable != nil && vuln.Vuln.Fixable != *filter.Fixable {
			continue
		}

		// Apply exploitable filter
		if filter.Exploitable != nil && vuln.Vuln.Exploitable != *filter.Exploitable {
			continue
		}

		// Apply package name filter
		if filter.PackageName != "" && !strings.Contains(vuln.Package.Name, filter.PackageName) {
			continue
		}

		// Apply CVE filter
		if filter.CVE != "" && !strings.Contains(vuln.Vuln.Name, filter.CVE) {
			continue
		}

		filtered = append(filtered, vuln)
	}

	return filtered, nil
}

// ListCriticalAndHighVulnerabilities retrieves only critical and high severity vulnerabilities that are fixable and exploitable
func (c *Client) ListCriticalAndHighVulnerabilities(resultID string) ([]Vulnerability, error) {
	fixable := true
	exploitable := true
	filter := VulnerabilityFilter{
		Severity:    []string{"critical", "high"},
		Fixable:     &fixable,
		Exploitable: &exploitable,
	}
	return c.ListVulnerabilitiesWithFilters(resultID, filter)
}

// ScanResultsResponse represents the scan results API response
type ScanResultsResponse struct {
	Data []ScanResult          `json:"data"`
	Page ScanResultsPageInfo   `json:"page,omitempty"`
}

// ScanResultsPageInfo represents pagination information for scan results API
type ScanResultsPageInfo struct {
	Next  string `json:"next,omitempty"`
	Total int    `json:"total,omitempty"`
}

// ScanResult represents a single scan result entry
type ScanResult struct {
	ResultID             string                 `json:"resultId"`
	CreatedAt            string                 `json:"createdAt"`
	PullString           string                 `json:"pullString,omitempty"`
	Scope                map[string]interface{} `json:"scope,omitempty"`
	VulnTotalBySeverity  VulnSeverityCount     `json:"vulnTotalBySeverity"`
}

// VulnSeverityCount represents vulnerability counts by severity
type VulnSeverityCount struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}


// ScanMetadata contains scan metadata
type ScanMetadata struct {
	PullString string `json:"pullString,omitempty"`
}


// PackageInfo represents package information
type PackageInfo struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// AcceptedRisksResponse represents the accepted risks API response
type AcceptedRisksResponse struct {
	Data []AcceptedRisk            `json:"data"`
	Page AcceptedRisksPageInfo     `json:"page"`
}

// AcceptedRisk represents an accepted risk entry
type AcceptedRisk struct {
	EntityValue    string `json:"entityValue"`
	ExpirationDate string `json:"expirationDate"`
	Description    string `json:"description"`
}

// VulnPkg represents a vulnerability-package pair from V2 API
type VulnPkg struct {
	ID             string    `json:"id"`
	Vuln           VulnV2    `json:"vuln"`
	Package        PackageV2 `json:"package"`
	FixedInVersion string    `json:"fixedInVersion,omitempty"`
}

// VulnPkgResponse represents the API response for vulnerability packages
type VulnPkgResponse struct {
	Page PageInfo  `json:"page"`
	Data []VulnPkg `json:"data"`
}

// AcceptedRisksPageInfo represents pagination information for accepted risks API
type AcceptedRisksPageInfo struct {
	Next string `json:"next,omitempty"`
}

// ListPipelineResults retrieves all pipeline scan results
func (c *Client) ListPipelineResults() ([]ScanResult, error) {
	return c.ListPipelineResultsWithDays(7) // デフォルト7日
}

// ListPipelineResultsWithDays retrieves pipeline scan results for specified days using pagination and client-side filtering
func (c *Client) ListPipelineResultsWithDays(days int) ([]ScanResult, error) {
	cutoffTime := time.Now().AddDate(0, 0, -days)
	allResults := []ScanResult{}
	cursor := ""
	limit := 100 // 小さめのページサイズで開始
	totalProcessed := 0
	maxPages := 200 // 期間フィルタリングがあるため制限を緩和
	pageCount := 0

	fmt.Printf("Starting pipeline cursor pagination fetch. Cutoff time: %s\n", cutoffTime.Format(time.RFC3339))

	for pageCount = 0; pageCount < maxPages; pageCount++ {
		fmt.Printf("Fetching page %d: cursor=%s, limit=%d\n", pageCount, cursor, limit)

		// cursorでページングデータ取得
		results, nextCursor, err := c.fetchPipelineResultsWithPagination(cursor, limit)
		if err != nil {
			return nil, err
		}

		totalProcessed += len(results)
		fmt.Printf("Retrieved %d records (total processed: %d)\n", len(results), totalProcessed)

		// 期間内データのみフィルタリング
		validResults := []ScanResult{}
		oldDataCount := 0

		for i, result := range results {
			createdAt, err := time.Parse(time.RFC3339, result.CreatedAt)
			if err != nil {
				fmt.Printf("Warning: Failed to parse CreatedAt '%s': %v\n", result.CreatedAt, err)
				continue
			}

			// 最初の3レコードだけデバッグ出力
			if i < 3 {
				fmt.Printf("Pipeline Record %d: ID=%s, CreatedAt=%s, Cutoff=%s, Valid=%t\n", i, result.ResultID,
					createdAt.Format(time.RFC3339), cutoffTime.Format(time.RFC3339), createdAt.After(cutoffTime))
			}

			if createdAt.After(cutoffTime) {
				validResults = append(validResults, result)
			} else {
				oldDataCount++
			}
		}

		allResults = append(allResults, validResults...)
		fmt.Printf("After filtering: %d valid, %d old records (total valid: %d)\n", len(validResults), oldDataCount, len(allResults))

		// 全データが期間外の場合は終了
		allOldData := oldDataCount == len(results)
		if allOldData && len(results) > 0 {
			fmt.Println("All pipeline data in this page is older than cutoff time. Stopping pagination.")
			break
		}
		if nextCursor == "" {
			fmt.Println("No more pipeline data available. Stopping pagination.")
			break
		}

		cursor = nextCursor
	}

	if pageCount >= maxPages {
		fmt.Printf("Reached maximum pages (%d). Consider increasing maxPages or refining query.\n", maxPages)
	}

	fmt.Printf("Pipeline pagination complete. Total valid results: %d\n", len(allResults))
	return allResults, nil
}

// ListRuntimeResults retrieves all runtime scan results
func (c *Client) ListRuntimeResults() ([]ScanResult, error) {
	return c.ListRuntimeResultsWithDays(7) // デフォルト7日
}

// ListRuntimeResultsWithLimits retrieves runtime scan results with asset type specific limits
func (c *Client) ListRuntimeResultsWithLimits(days int, workloadLimit, hostLimit, containerLimit int) ([]ScanResult, error) {
	allResults := []ScanResult{}

	// Asset types to process
	assetTypes := []struct {
		name  string
		limit int
	}{
		{"workload", workloadLimit},
		{"host", hostLimit},
		{"container", containerLimit},
	}

	for _, assetType := range assetTypes {
		if assetType.limit < 0 {
			continue // Skip negative limits
		}

		fmt.Printf("Fetching %s results (limit: %d)...\n", assetType.name, assetType.limit)

		results, err := c.fetchRuntimeResultsByAssetType(assetType.name, assetType.limit)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch %s results: %w", assetType.name, err)
		}

		fmt.Printf("Retrieved %d %s results\n", len(results), assetType.name)
		allResults = append(allResults, results...)
	}

	fmt.Printf("Total runtime results: %d\n", len(allResults))
	return allResults, nil
}

// ListRuntimeResultsWithDays retrieves runtime scan results for specified days using pagination and client-side filtering
func (c *Client) ListRuntimeResultsWithDays(days int) ([]ScanResult, error) {
	cutoffTime := time.Now().AddDate(0, 0, -days)
	allResults := []ScanResult{}
	cursor := ""
	limit := 100 // 小さめのページサイズで開始
	totalProcessed := 0
	maxPages := 50 // 安全のため最大ページ数制限
	pageCount := 0

	fmt.Printf("Starting runtime cursor pagination fetch. Cutoff time: %s\n", cutoffTime.Format(time.RFC3339))

	for pageCount = 0; pageCount < maxPages; pageCount++ {
		fmt.Printf("Fetching runtime page %d: cursor=%s, limit=%d\n", pageCount, cursor, limit)

		// cursorでページングデータ取得
		results, nextCursor, err := c.fetchRuntimeResultsWithPagination(cursor, limit)
		if err != nil {
			return nil, err
		}

		totalProcessed += len(results)
		fmt.Printf("Retrieved %d runtime records (total processed: %d)\n", len(results), totalProcessed)

		// Runtime APIにはcreatedAtフィールドがないため、全データを有効とする
		validResults := results

		// デバッグ出力：最初の3レコード
		for i, result := range results {
			if i < 3 {
				fmt.Printf("Runtime Record %d: resultId=%s (no createdAt field)\n", i, result.ResultID)
			}
		}

		allResults = append(allResults, validResults...)
		fmt.Printf("After runtime filtering: %d valid records (total valid: %d)\n", len(validResults), len(allResults))

		// Runtime APIは期間フィルタリングなし、カーソルの終了のみチェック
		if nextCursor == "" {
			fmt.Println("No more runtime data available. Stopping pagination.")
			break
		}

		cursor = nextCursor
	}

	if pageCount >= maxPages {
		fmt.Printf("Reached maximum pages (%d). Consider increasing maxPages or refining query.\n", maxPages)
	}

	fmt.Printf("Runtime pagination complete. Total valid results: %d\n", len(allResults))
	return allResults, nil
}

// fetchPipelineResultsWithPagination retrieves a single page of pipeline results using cursor
func (c *Client) fetchPipelineResultsWithPagination(cursor string, limit int) ([]ScanResult, string, error) {
	var endpoint string
	if cursor == "" {
		endpoint = fmt.Sprintf("/pipeline-results?limit=%d", limit)
	} else {
		endpoint = fmt.Sprintf("/pipeline-results?limit=%d&cursor=%s", limit, cursor)
	}

	resp, err := c.makeRequest("GET", endpoint, nil)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var scanResp ScanResultsResponse
	if err := json.NewDecoder(resp.Body).Decode(&scanResp); err != nil {
		return nil, "", fmt.Errorf("failed to decode response: %w", err)
	}

	// 次のカーソルを返す（なければ空文字列）
	nextCursor := scanResp.Page.Next

	return scanResp.Data, nextCursor, nil
}

// fetchRuntimeResultsWithPagination retrieves a single page of runtime results using cursor
func (c *Client) fetchRuntimeResultsWithPagination(cursor string, limit int) ([]ScanResult, string, error) {
	var endpoint string
	if cursor == "" {
		endpoint = fmt.Sprintf("/runtime-results?limit=%d", limit)
	} else {
		endpoint = fmt.Sprintf("/runtime-results?limit=%d&cursor=%s", limit, cursor)
	}

	resp, err := c.makeRequest("GET", endpoint, nil)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var scanResp ScanResultsResponse
	if err := json.NewDecoder(resp.Body).Decode(&scanResp); err != nil {
		return nil, "", fmt.Errorf("failed to decode response: %w", err)
	}

	// 次のカーソルを返す（なければ空文字列）
	nextCursor := scanResp.Page.Next

	return scanResp.Data, nextCursor, nil
}

// fetchRuntimeResultsByAssetType retrieves runtime results filtered by asset type with limit
func (c *Client) fetchRuntimeResultsByAssetType(assetType string, limit int) ([]ScanResult, error) {
	if limit == 0 {
		// 0 means unlimited, use large number for practical purposes
		limit = 10000
	}

	allResults := []ScanResult{}
	cursor := ""
	pageSize := 100
	totalProcessed := 0

	for totalProcessed < limit {
		// Calculate remaining items needed
		remaining := limit - totalProcessed
		currentPageSize := pageSize
		if remaining < pageSize {
			currentPageSize = remaining
		}

		// Build endpoint with asset type filter
		var endpoint string
		filterParam := fmt.Sprintf("asset.type%%3D%%22%s%%22", assetType)
		if cursor == "" {
			endpoint = fmt.Sprintf("/runtime-results?limit=%d&filter=%s", currentPageSize, filterParam)
		} else {
			endpoint = fmt.Sprintf("/runtime-results?limit=%d&cursor=%s&filter=%s", currentPageSize, cursor, filterParam)
		}

		resp, err := c.makeRequest("GET", endpoint, nil)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
		}

		var scanResp ScanResultsResponse
		if err := json.NewDecoder(resp.Body).Decode(&scanResp); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}

		allResults = append(allResults, scanResp.Data...)
		totalProcessed += len(scanResp.Data)

		// Check if we have more data or reached the limit
		if scanResp.Page.Next == "" || len(scanResp.Data) == 0 {
			break
		}

		cursor = scanResp.Page.Next
	}

	return allResults, nil
}

// GetScanResultVulnerabilities retrieves vulnerabilities for a specific scan result using V2 API
func (c *Client) GetScanResultVulnerabilities(resultID string) ([]Vulnerability, error) {
	endpoint := fmt.Sprintf("/api/scanning/scanresults/v2/results/%s/vulnPkgs", resultID)
	resp, err := c.makeRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("scan result not found: %s", resultID)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var vulnResponse VulnPkgResponse
	if err := json.NewDecoder(resp.Body).Decode(&vulnResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert VulnPkg to Vulnerability for compatibility
	vulnerabilities := make([]Vulnerability, 0, len(vulnResponse.Data))
	for _, vulnPkg := range vulnResponse.Data {
		vuln := Vulnerability{
			ID: vulnPkg.ID,
			Vuln: VulnV2{
				Name:           vulnPkg.Vuln.Name,
				Severity:       vulnPkg.Vuln.Severity,
				CvssScore:      vulnPkg.Vuln.CvssScore,
				DisclosureDate: vulnPkg.Vuln.DisclosureDate,
				Exploitable:    vulnPkg.Vuln.Exploitable,
			},
			Package: PackageV2{
				Name:    vulnPkg.Package.Name,
				Version: vulnPkg.Package.Version,
				Type:    vulnPkg.Package.Type,
			},
		}

		// Set FixedInVersion and compute Fixable
		if vulnPkg.FixedInVersion != "" {
			vuln.FixedInVersion = &vulnPkg.FixedInVersion
			vuln.Vuln.Fixable = true
		} else {
			vuln.Vuln.Fixable = false
		}

		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities, nil
}

// ListAcceptedRisks retrieves all accepted risks with pagination
func (c *Client) ListAcceptedRisks() ([]AcceptedRisk, error) {
	allRisks := []AcceptedRisk{}
	cursor := ""

	for {
		endpoint := "/accepted-risks?limit=200"
		if cursor != "" {
			endpoint += fmt.Sprintf("&cursor=%s", cursor)
		}

		resp, err := c.makeRequest("GET", endpoint, nil)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
		}

		var acceptedResp AcceptedRisksResponse
		if err := json.NewDecoder(resp.Body).Decode(&acceptedResp); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}

		allRisks = append(allRisks, acceptedResp.Data...)

		// Check if there's a next page
		if acceptedResp.Page.Next == "" {
			break
		}
		cursor = acceptedResp.Page.Next
	}

	return allRisks, nil
}

// CreateAcceptedRisk creates a new accepted risk
func (c *Client) CreateAcceptedRisk(entityValue string, expirationDays int, description string) error {
	expirationDate := time.Now().AddDate(0, 0, expirationDays).Format("2006-01-02")

	body := map[string]interface{}{
		"context":        []interface{}{},
		"entityType":     "vulnerability",
		"entityValue":    entityValue,
		"expirationDate": expirationDate,
		"description":    description,
		"reason":         "RiskOwned",
	}

	resp, err := c.makeRequest("POST", "/accepted-risks", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create accepted risk: status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// GetVulnPackagesV2 retrieves vulnerability packages using the v2 scanning API
func (c *Client) GetVulnPackagesV2(resultID string, limit int, offset int, sortBy string, order string) (*VulnPackageResponseV2, error) {
	endpoint := fmt.Sprintf("/api/scanning/scanresults/v2/results/%s/vulnPkgs", resultID)

	// Build query parameters
	params := fmt.Sprintf("?limit=%d&offset=%d", limit, offset)
	if sortBy != "" {
		params += fmt.Sprintf("&sort=%s", sortBy)
	}
	if order != "" {
		params += fmt.Sprintf("&order=%s", order)
	}

	endpoint += params

	resp, err := c.makeRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var vulnResp VulnPackageResponseV2
	if err := json.NewDecoder(resp.Body).Decode(&vulnResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &vulnResp, nil
}

// GetAllVulnPackagesV2 retrieves all vulnerability packages for a scan result with pagination
func (c *Client) GetAllVulnPackagesV2(resultID string) ([]Vulnerability, error) {
	var allVulns []Vulnerability
	limit := 100
	offset := 0

	for {
		resp, err := c.GetVulnPackagesV2(resultID, limit, offset, "vulnSeverity", "desc")
		if err != nil {
			return nil, fmt.Errorf("failed to get vulnerability packages at offset %d: %w", offset, err)
		}

		// Convert VulnPackageV2 to Vulnerability and set fixable based on fixedInVersion
		for _, vulnPkg := range resp.Data {
			vuln := Vulnerability{
				ID:             vulnPkg.ID,
				Vuln:           vulnPkg.Vuln,
				Package:        vulnPkg.Package,
				FixedInVersion: nil,
			}

			// Set FixedInVersion and compute Fixable
			if vulnPkg.FixedInVersion != "" {
				vuln.FixedInVersion = &vulnPkg.FixedInVersion
				vuln.Vuln.Fixable = true
			} else {
				vuln.Vuln.Fixable = false
			}

			allVulns = append(allVulns, vuln)
		}

		// Check if we've retrieved all data
		if len(resp.Data) < limit || offset + len(resp.Data) >= resp.Page.Matched {
			break
		}

		offset += limit
	}

	return allVulns, nil
}

// Helper function to convert severity int to string
func (v VulnV2) SeverityString() string {
	switch v.Severity {
	case 1:
		return "low"
	case 2:
		return "medium"
	case 3:
		return "high"
	case 4:
		return "critical"
	case 5:
		return "negligible"
	case 6:
		return "none"
	case 7:
		return "unknown"
	default:
		return fmt.Sprintf("severity_%d", v.Severity)
	}
}
