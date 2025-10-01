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
	ID             string    `json:"id"`
	Vuln           VulnV2    `json:"vuln"`
	Package        PackageV2 `json:"package"`
	FixedInVersion *string   `json:"fixedInVersion"` // Use pointer to detect null values
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
	Name              string                  `json:"name"`
	Severity          int                     `json:"severity"` // 1=low, 2=medium, 3=high, 4=critical
	CvssVersion       string                  `json:"cvssVersion"`
	CvssScore         float64                 `json:"cvssScore"`
	EpssScore         *EpssScore              `json:"epssScore,omitempty"`
	Exploitable       bool                    `json:"exploitable"`
	CisaKev           bool                    `json:"cisakev"`
	DisclosureDate    string                  `json:"disclosureDate"`
	AcceptedRisks     []interface{}           `json:"acceptedRisks"`
	ProvidersMetadata map[string]ProviderMeta `json:"providersMetadata"`
	Fixable           bool                    `json:"-"` // Computed based on FixedInVersion
}

type EpssScore struct {
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
	Timestamp  string  `json:"timestamp"`
}

type ProviderMeta struct {
	PublishDate *string    `json:"publishDate,omitempty"`
	CvssScore   *CvssScore `json:"cvssScore,omitempty"`
	Severity    *string    `json:"severity,omitempty"`
	EpssScore   *EpssScore `json:"epssScore,omitempty"`
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

// VulnerabilityFilter represents filter options for V2 API
type VulnerabilityFilter struct {
	Severity    []string `json:"severity,omitempty"` // 1=low, 2=medium, 3=high, 4=critical
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

// ListVulnerabilities retrieves all vulnerabilities from a scan result using V1 API
func (c *Client) ListVulnerabilities(resultID string) ([]Vulnerability, error) {
	return c.GetScanResultVulnerabilities(resultID)
}

// GetVulnerability retrieves a specific vulnerability from a scan result by ID using V1 API
func (c *Client) GetVulnerability(resultID, vulnID string) (*Vulnerability, error) {
	allVulns, err := c.GetScanResultVulnerabilities(resultID)
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

// ListVulnerabilitiesWithFilters retrieves vulnerabilities with multiple filters using V1 API
func (c *Client) ListVulnerabilitiesWithFilters(resultID string, filter VulnerabilityFilter) ([]Vulnerability, error) {
	allVulns, err := c.GetScanResultVulnerabilities(resultID)
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
	Data []ScanResult        `json:"data"`
	Page ScanResultsPageInfo `json:"page,omitempty"`
}

// ScanResultsPageInfo represents pagination information for scan results API
type ScanResultsPageInfo struct {
	Next  string `json:"next,omitempty"`
	Total int    `json:"total,omitempty"`
}

// ScanResult represents a single scan result entry
type ScanResult struct {
	ResultID                   string                 `json:"resultId"`
	CreatedAt                  string                 `json:"createdAt,omitempty"`
	PullString                 string                 `json:"pullString,omitempty"`
	ImageID                    string                 `json:"imageId,omitempty"`
	PolicyEvaluationResult     string                 `json:"policyEvaluationResult,omitempty"`
	Scope                      map[string]interface{} `json:"scope,omitempty"`
	VulnTotalBySeverity        VulnSeverityCount      `json:"vulnTotalBySeverity"`
	MainAssetName              string                 `json:"mainAssetName,omitempty"`
	ResourceID                 string                 `json:"resourceId,omitempty"`
	SbomID                     string                 `json:"sbomId,omitempty"`
	IsRiskSpotlightEnabled     bool                   `json:"isRiskSpotlightEnabled,omitempty"`
	RunningVulnTotalBySeverity *VulnSeverityCount     `json:"runningVulnTotalBySeverity,omitempty"`
}

// VulnSeverityCount represents vulnerability counts by severity
type VulnSeverityCount struct {
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Negligible int `json:"negligible,omitempty"`
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
	Data []AcceptedRisk        `json:"data"`
	Page AcceptedRisksPageInfo `json:"page"`
}

// AcceptedRisk represents an accepted risk entry
type AcceptedRisk struct {
	EntityValue    string `json:"entityValue"`
	ExpirationDate string `json:"expirationDate"`
	Description    string `json:"description"`
}

// AcceptedRisksPageInfo represents pagination information for accepted risks API
type AcceptedRisksPageInfo struct {
	Next string `json:"next,omitempty"`
}

// FullScanResult represents the complete scan result from /secure/vulnerability/v1/results/{resultId}
type FullScanResult struct {
	AssetType       string                       `json:"assetType"`
	Stage           string                       `json:"stage"`
	Metadata        ScanResultMetadata           `json:"metadata"`
	Packages        map[string]Package           `json:"packages"`
	Vulnerabilities map[string]VulnerabilityInfo `json:"vulnerabilities"`
	Layers          map[string]Layer             `json:"layers,omitempty"`
	BaseImages      map[string]BaseImage         `json:"baseImages,omitempty"`
	Policies        PolicyEvaluations            `json:"policies,omitempty"`
	RiskAccepts     map[string]RiskAccept        `json:"riskAccepts,omitempty"`
	Producer        Producer                     `json:"producer,omitempty"`
}

// ScanResultMetadata represents the metadata section of a full scan result
type ScanResultMetadata struct {
	Architecture string            `json:"architecture,omitempty"`
	Author       string            `json:"author,omitempty"`
	BaseOS       string            `json:"baseOs,omitempty"`
	CreatedAt    string            `json:"createdAt,omitempty"`
	Digest       string            `json:"digest,omitempty"`
	ImageID      string            `json:"imageId,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	OS           string            `json:"os,omitempty"`
	PullString   string            `json:"pullString,omitempty"`
	Size         int64             `json:"size,omitempty"`
}

// Package represents a package in the scan result
type Package struct {
	Name                string   `json:"name"`
	Version             string   `json:"version"`
	Type                string   `json:"type"`
	Path                string   `json:"path,omitempty"`
	License             string   `json:"license,omitempty"`
	LayerRef            string   `json:"layerRef,omitempty"`
	IsRunning           bool     `json:"isRunning,omitempty"`
	IsRemoved           bool     `json:"isRemoved,omitempty"`
	SuggestedFix        string   `json:"suggestedFix,omitempty"`
	VulnerabilitiesRefs []string `json:"vulnerabilitiesRefs,omitempty"`
	RiskAcceptRefs      []string `json:"riskAcceptRefs,omitempty"`
}

// VulnerabilityInfo represents a vulnerability in the scan result
type VulnerabilityInfo struct {
	Name              string                 `json:"name"`
	Severity          string                 `json:"severity"`
	DisclosureDate    string                 `json:"disclosureDate,omitempty"`
	SolutionDate      string                 `json:"solutionDate,omitempty"`
	FixVersion        string                 `json:"fixVersion,omitempty"`
	Exploitable       bool                   `json:"exploitable,omitempty"`
	PackageRef        string                 `json:"packageRef,omitempty"`
	MainProvider      string                 `json:"mainProvider,omitempty"`
	CvssScore         *CvssScore             `json:"cvssScore,omitempty"`
	CisaKev           *CisaKev               `json:"cisaKev,omitempty"`
	Exploit           *ExploitInfo           `json:"exploit,omitempty"`
	ProvidersMetadata map[string]interface{} `json:"providersMetadata,omitempty"`
	RiskAcceptRefs    []string               `json:"riskAcceptRefs,omitempty"`
}

// CisaKev represents CISA Known Exploited Vulnerabilities information
type CisaKev struct {
	DueDate                    string `json:"dueDate,omitempty"`
	KnownRansomwareCampaignUse bool   `json:"knownRansomwareCampaignUse,omitempty"`
	PublishDate                string `json:"publishDate,omitempty"`
}

// ExploitInfo represents exploit information
type ExploitInfo struct {
	Links           []string `json:"links,omitempty"`
	PublicationDate string   `json:"publicationDate,omitempty"`
}

// Layer represents a container image layer
type Layer struct {
	ID            string   `json:"id,omitempty"`
	Digest        string   `json:"digest,omitempty"`
	Command       string   `json:"command,omitempty"`
	Size          int64    `json:"size,omitempty"`
	BaseImagesRef []string `json:"baseImagesRef,omitempty"`
}

// BaseImage represents a base image
type BaseImage struct {
	PullStrings []string `json:"pullStrings,omitempty"`
}

// PolicyEvaluations represents policy evaluation results
type PolicyEvaluations struct {
	GlobalEvaluation string             `json:"globalEvaluation,omitempty"`
	Evaluations      []PolicyEvaluation `json:"evaluations,omitempty"`
}

// PolicyEvaluation represents a single policy evaluation
type PolicyEvaluation struct {
	Identifier  string         `json:"identifier,omitempty"`
	Name        string         `json:"name,omitempty"`
	Description string         `json:"description,omitempty"`
	Evaluation  string         `json:"evaluation,omitempty"`
	CreatedAt   string         `json:"createdAt,omitempty"`
	UpdatedAt   string         `json:"updatedAt,omitempty"`
	Bundles     []PolicyBundle `json:"bundles,omitempty"`
}

// PolicyBundle represents a policy bundle
type PolicyBundle struct {
	Identifier string       `json:"identifier,omitempty"`
	Name       string       `json:"name,omitempty"`
	Type       string       `json:"type,omitempty"`
	Rules      []PolicyRule `json:"rules,omitempty"`
}

// PolicyRule represents a policy rule
type PolicyRule struct {
	RuleID           string                   `json:"ruleId,omitempty"`
	RuleType         string                   `json:"ruleType,omitempty"`
	Description      string                   `json:"description,omitempty"`
	EvaluationResult string                   `json:"evaluationResult,omitempty"`
	FailureType      string                   `json:"failureType,omitempty"`
	Failures         []map[string]interface{} `json:"failures,omitempty"`
	Predicates       []map[string]interface{} `json:"predicates,omitempty"`
}

// RiskAccept represents an accepted risk
type RiskAccept struct {
	ID             string                   `json:"id,omitempty"`
	EntityType     string                   `json:"entityType,omitempty"`
	EntityValue    string                   `json:"entityValue,omitempty"`
	Reason         string                   `json:"reason,omitempty"`
	Description    string                   `json:"description,omitempty"`
	ExpirationDate string                   `json:"expirationDate,omitempty"`
	Status         string                   `json:"status,omitempty"`
	CreatedAt      string                   `json:"createdAt,omitempty"`
	UpdatedAt      string                   `json:"updatedAt,omitempty"`
	Context        []map[string]interface{} `json:"context,omitempty"`
}

// Producer represents the producer information
type Producer struct {
	ProducedAt string `json:"producedAt,omitempty"`
}

// ListPipelineResults retrieves all pipeline scan results
func (c *Client) ListPipelineResults() ([]ScanResult, error) {
	return c.ListPipelineResultsWithDays(7) // デフォルト7日
}

// ListPipelineResultsWithDays retrieves pipeline scan results for specified days using pagination and client-side filtering
func (c *Client) ListPipelineResultsWithDays(days int) ([]ScanResult, error) {
	return c.ListPipelineResultsWithFilter(days, "")
}

// ListPipelineResultsWithFilter retrieves pipeline scan results with optional freeText filter
func (c *Client) ListPipelineResultsWithFilter(days int, freeTextFilter string) ([]ScanResult, error) {
	cutoffTime := time.Now().AddDate(0, 0, -days)
	allResults := []ScanResult{}
	cursor := ""
	limit := 100 // 小さめのページサイズで開始
	totalProcessed := 0
	maxPages := 200 // 期間フィルタリングがあるため制限を緩和
	pageCount := 0

	fmt.Printf("Starting pipeline cursor pagination fetch. Cutoff time: %s\n", cutoffTime.Format(time.RFC3339))
	if freeTextFilter != "" {
		fmt.Printf("Filter: freeText in (\"%s\")\n", freeTextFilter)
	}

	for pageCount = 0; pageCount < maxPages; pageCount++ {
		fmt.Printf("Fetching page %d: cursor=%s, limit=%d\n", pageCount, cursor, limit)

		// cursorでページングデータ取得
		results, nextCursor, err := c.fetchPipelineResultsWithPagination(cursor, limit, freeTextFilter)
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
func (c *Client) fetchPipelineResultsWithPagination(cursor string, limit int, freeTextFilter string) ([]ScanResult, string, error) {
	var endpoint string

	// Build base query parameters
	params := fmt.Sprintf("limit=%d", limit)
	if cursor != "" {
		params += fmt.Sprintf("&cursor=%s", cursor)
	}

	// Add filter parameter if freeTextFilter is provided
	if freeTextFilter != "" {
		// URL encode the filter: filter=freeText in ("value")
		filterValue := fmt.Sprintf("freeText in (\"%s\")", freeTextFilter)
		// Simple URL encoding for the filter parameter
		filterValue = strings.ReplaceAll(filterValue, " ", "%20")
		filterValue = strings.ReplaceAll(filterValue, "\"", "%22")
		filterValue = strings.ReplaceAll(filterValue, "(", "%28")
		filterValue = strings.ReplaceAll(filterValue, ")", "%29")
		params += fmt.Sprintf("&filter=%s", filterValue)
	}

	endpoint = fmt.Sprintf("/pipeline-results?%s", params)

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

// GetFullScanResult retrieves the complete scan result using V1 API
func (c *Client) GetFullScanResult(resultID string) (*FullScanResult, error) {
	endpoint := fmt.Sprintf("/results/%s", resultID)
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

	var fullResult FullScanResult
	if err := json.NewDecoder(resp.Body).Decode(&fullResult); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &fullResult, nil
}

// GetScanResultVulnerabilities retrieves vulnerabilities for a specific scan result using V1 API
// This method constructs vulnerability-package pairs from the full scan result
func (c *Client) GetScanResultVulnerabilities(resultID string) ([]Vulnerability, error) {
	fullResult, err := c.GetFullScanResult(resultID)
	if err != nil {
		return nil, err
	}

	// packages と vulnerabilities の参照関係を辿って Vulnerability リストを構築
	vulnerabilities := make([]Vulnerability, 0)

	for pkgID, pkg := range fullResult.Packages {
		for _, vulnRef := range pkg.VulnerabilitiesRefs {
			vulnInfo, ok := fullResult.Vulnerabilities[vulnRef]
			if !ok {
				continue // 参照が見つからない場合はスキップ
			}

			// VulnerabilityInfo から Vulnerability 構造体に変換
			vuln := Vulnerability{
				ID: vulnRef,
				Vuln: VulnV2{
					Name:           vulnInfo.Name,
					Severity:       severityStringToInt(vulnInfo.Severity),
					CvssScore:      0, // CvssScoreから取得
					DisclosureDate: vulnInfo.DisclosureDate,
					Exploitable:    vulnInfo.Exploitable,
					Fixable:        vulnInfo.FixVersion != "",
				},
				Package: PackageV2{
					ID:      pkgID,
					Name:    pkg.Name,
					Version: pkg.Version,
					Type:    pkg.Type,
					Running: pkg.IsRunning,
					Removed: pkg.IsRemoved,
				},
			}

			// CvssScore を設定
			if vulnInfo.CvssScore != nil {
				vuln.Vuln.CvssScore = vulnInfo.CvssScore.Score
				vuln.Vuln.CvssVersion = vulnInfo.CvssScore.Version
			}

			// FixedInVersion を設定
			if vulnInfo.FixVersion != "" {
				vuln.FixedInVersion = &vulnInfo.FixVersion
			}

			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	return vulnerabilities, nil
}

// severityStringToInt converts severity string to integer
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
	case "none":
		return 6
	default:
		return 0
	}
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
