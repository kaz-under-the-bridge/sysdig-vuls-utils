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

// Vulnerability represents a vulnerability from Sysdig API
type Vulnerability struct {
	ID               string                 `json:"id"`
	CVE              string                 `json:"cve,omitempty"`
	Severity         string                 `json:"severity"`
	Status           string                 `json:"status"`
	Description      string                 `json:"description"`
	Packages         []string               `json:"packages,omitempty"`
	Score            float64                `json:"score,omitempty"`
	Vector           string                 `json:"vector,omitempty"`
	PublishedAt      string                 `json:"publishedAt,omitempty"`
	UpdatedAt        string                 `json:"updatedAt,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	Fixable          bool                   `json:"fixable,omitempty"`
	Exploitable      bool                   `json:"exploitable,omitempty"`
	FixedVersion     string                 `json:"fixedVersion,omitempty"`
	DetectionSources []DetectionSource      `json:"detectionSources,omitempty"`
	AWSResources     []AWSResource          `json:"awsResources,omitempty"`
	ContainerInfo    *ContainerInfo         `json:"containerInfo,omitempty"`
}

// DetectionSource represents where a vulnerability was detected
type DetectionSource struct {
	Type        string `json:"type"`        // "runtime", "container", "image_repo"
	Location    string `json:"location"`
	ClusterName string `json:"clusterName,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	PodName     string `json:"podName,omitempty"`
}

// AWSResource represents AWS resource information
type AWSResource struct {
	AccountID    string `json:"accountId"`
	Region       string `json:"region,omitempty"`
	ResourceType string `json:"resourceType"` // "EC2", "Lambda", "ECS", "EKS", "ECR"
	ResourceID   string `json:"resourceId"`
	ResourceName string `json:"resourceName,omitempty"`
	InstanceID   string `json:"instanceId,omitempty"` // For EC2
	ClusterArn   string `json:"clusterArn,omitempty"` // For ECS/EKS
	FunctionArn  string `json:"functionArn,omitempty"` // For Lambda
}

// ContainerInfo represents container information
type ContainerInfo struct {
	ImageName   string `json:"imageName"`
	ImageTag    string `json:"imageTag"`
	ImageID     string `json:"imageId,omitempty"`
	Registry    string `json:"registry,omitempty"`
	ImageDigest string `json:"imageDigest,omitempty"`
}

// V2 API structures based on scanning/scanresults/v2 endpoint
type VulnPackageResponseV2 struct {
	Page PageInfoV2       `json:"page"`
	Data []VulnPackageV2  `json:"data"`
}

type PageInfoV2 struct {
	Returned int `json:"returned"`
	Offset   int `json:"offset"`
	Matched  int `json:"matched"`
}

type VulnPackageV2 struct {
	ID             string     `json:"id"`
	Vuln           VulnV2     `json:"vuln"`
	Package        PackageV2  `json:"package"`
	FixedInVersion string     `json:"fixedInVersion,omitempty"`
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

// VulnerabilityResponse represents the API response for vulnerability lists
type VulnerabilityResponse struct {
	Data       []Vulnerability `json:"data"`
	Page       int             `json:"page"`
	TotalPages int             `json:"totalPages"`
	Total      int             `json:"total"`
}

// VulnerabilityFilter represents filter options for listing vulnerabilities
type VulnerabilityFilter struct {
	Severity     []string `json:"severity,omitempty"`     // "critical", "high", "medium", "low"
	Fixable      *bool    `json:"fixable,omitempty"`
	Exploitable  *bool    `json:"exploitable,omitempty"`
	PackageName  string   `json:"packageName,omitempty"`
	CVE          string   `json:"cve,omitempty"`
	ResourceType string   `json:"resourceType,omitempty"` // "EC2", "Lambda", "ECS", "EKS", "ECR"
	AccountID    string   `json:"accountId,omitempty"`
}

// NewClient creates a new Sysdig API client
func NewClient(baseURL, apiToken string) *Client {
	return &Client{
		baseURL:  baseURL,
		apiToken: apiToken,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
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

// ListVulnerabilities retrieves all vulnerabilities
func (c *Client) ListVulnerabilities() ([]Vulnerability, error) {
	resp, err := c.makeRequest("GET", "/vulnerabilities", nil)
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

// GetVulnerability retrieves a specific vulnerability by ID
func (c *Client) GetVulnerability(vulnID string) (*Vulnerability, error) {
	endpoint := fmt.Sprintf("/vulnerabilities/%s", vulnID)
	resp, err := c.makeRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("vulnerability not found: %s", vulnID)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var vuln Vulnerability
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &vuln, nil
}

// UpdateVulnerability updates a vulnerability with new data
func (c *Client) UpdateVulnerability(vulnID string, updates map[string]interface{}) error {
	endpoint := fmt.Sprintf("/vulnerabilities/%s", vulnID)
	resp, err := c.makeRequest("PATCH", endpoint, updates)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("vulnerability not found: %s", vulnID)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

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

// ListVulnerabilitiesWithFilters retrieves vulnerabilities with multiple filters
func (c *Client) ListVulnerabilitiesWithFilters(filter VulnerabilityFilter) ([]Vulnerability, error) {
	endpoint := "/vulnerabilities?"
	params := []string{}

	// Add severity filter
	if len(filter.Severity) > 0 {
		for _, sev := range filter.Severity {
			params = append(params, fmt.Sprintf("severity=%s", sev))
		}
	}

	// Add fixable filter
	if filter.Fixable != nil {
		params = append(params, fmt.Sprintf("fixable=%t", *filter.Fixable))
	}

	// Add exploitable filter
	if filter.Exploitable != nil {
		params = append(params, fmt.Sprintf("exploitable=%t", *filter.Exploitable))
	}

	// Add package name filter
	if filter.PackageName != "" {
		params = append(params, fmt.Sprintf("package=%s", filter.PackageName))
	}

	// Add CVE filter
	if filter.CVE != "" {
		params = append(params, fmt.Sprintf("cve=%s", filter.CVE))
	}

	// Add AWS resource type filter
	if filter.ResourceType != "" {
		params = append(params, fmt.Sprintf("resourceType=%s", filter.ResourceType))
	}

	// Add AWS account ID filter
	if filter.AccountID != "" {
		params = append(params, fmt.Sprintf("accountId=%s", filter.AccountID))
	}

	// Construct the final endpoint
	if len(params) > 0 {
		endpoint = fmt.Sprintf("/vulnerabilities?%s", joinParams(params))
	} else {
		endpoint = "/vulnerabilities"
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

	var vulnResp VulnerabilityResponse
	if err := json.NewDecoder(resp.Body).Decode(&vulnResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return vulnResp.Data, nil
}

// ListCriticalAndHighVulnerabilities retrieves only critical and high severity vulnerabilities that are fixable and exploitable
func (c *Client) ListCriticalAndHighVulnerabilities() ([]Vulnerability, error) {
	fixable := true
	exploitable := true
	filter := VulnerabilityFilter{
		Severity:    []string{"critical", "high"},
		Fixable:     &fixable,
		Exploitable: &exploitable,
	}
	return c.ListVulnerabilitiesWithFilters(filter)
}

// joinParams joins URL parameters with &
func joinParams(params []string) string {
	result := ""
	for i, param := range params {
		if i > 0 {
			result += "&"
		}
		result += param
	}
	return result
}

// ScanResultsResponse represents the scan results API response
type ScanResultsResponse struct {
	Data []ScanResult `json:"data"`
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

// DetailedScanResponse represents the detailed scan result response
type DetailedScanResponse struct {
	Metadata        ScanMetadata           `json:"metadata"`
	Vulnerabilities map[string]VulnDetail  `json:"vulnerabilities"`
	Packages        map[string]PackageInfo `json:"packages"`
	RiskAccepts     map[string]interface{} `json:"riskAccepts"`
}

// DetailedScanResponseV1Beta1 represents the v1beta1 detailed scan result response with enhanced fields
type DetailedScanResponseV1Beta1 struct {
	Metadata                     ScanMetadata            `json:"metadata"`
	Vulnerabilities             map[string]VulnDetailV1Beta1 `json:"vulnerabilities"`
	Packages                    map[string]PackageInfo  `json:"packages"`
	RiskAccepts                 map[string]interface{}  `json:"riskAccepts"`
	VulnTotalBySeverity         VulnSeverityCount       `json:"vulnTotalBySeverity"`
	FixableVulnTotalBySeverity  VulnSeverityCount       `json:"fixableVulnTotalBySeverity"`
	ExploitableVulnTotalBySeverity VulnSeverityCount    `json:"exploitableVulnTotalBySeverity,omitempty"`
}

// ScanMetadata contains scan metadata
type ScanMetadata struct {
	PullString string `json:"pullString,omitempty"`
}

// VulnDetail represents detailed vulnerability information
type VulnDetail struct {
	Name           string `json:"name"`
	Severity       string `json:"severity"`
	DisclosureDate string `json:"disclosureDate"`
	PackageRef     string `json:"packageRef"`
	Fixable        bool   `json:"fixable,omitempty"`
	Exploitable    bool   `json:"exploitable,omitempty"`
	FixedVersion   string `json:"fixedVersion,omitempty"`
}

// VulnDetailV1Beta1 represents detailed vulnerability information from v1beta1 endpoint
type VulnDetailV1Beta1 struct {
	Name           string `json:"name"`
	Severity       string `json:"severity"`
	DisclosureDate string `json:"disclosureDate"`
	PackageRef     string `json:"packageRef"`
	Fixable        bool   `json:"fixable,omitempty"`
	Exploitable    bool   `json:"exploitable,omitempty"`
	FixedVersion   string `json:"fixedVersion,omitempty"`
	// Additional fields that might be in v1beta1
	CVSS           float64 `json:"cvss,omitempty"`
	Description    string  `json:"description,omitempty"`
}

// PackageInfo represents package information
type PackageInfo struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// AcceptedRisksResponse represents the accepted risks API response
type AcceptedRisksResponse struct {
	Data []AcceptedRisk `json:"data"`
	Page PageInfo       `json:"page"`
}

// AcceptedRisk represents an accepted risk entry
type AcceptedRisk struct {
	EntityValue    string `json:"entityValue"`
	ExpirationDate string `json:"expirationDate"`
	Description    string `json:"description"`
}

// PageInfo represents pagination information
type PageInfo struct {
	Next string `json:"next,omitempty"`
}

// ListPipelineResults retrieves all pipeline scan results
func (c *Client) ListPipelineResults() ([]ScanResult, error) {
	return c.ListPipelineResultsWithDays(7) // デフォルト7日
}

// ListPipelineResultsWithDays retrieves pipeline scan results for specified days
func (c *Client) ListPipelineResultsWithDays(days int) ([]ScanResult, error) {
	// Calculate date range
	endTime := time.Now()
	startTime := endTime.AddDate(0, 0, -days)

	endpoint := fmt.Sprintf("/pipeline-results?from=%s&to=%s",
		startTime.Format("2006-01-02T15:04:05Z"),
		endTime.Format("2006-01-02T15:04:05Z"))

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

	return scanResp.Data, nil
}

// ListRuntimeResults retrieves all runtime scan results
func (c *Client) ListRuntimeResults() ([]ScanResult, error) {
	return c.ListRuntimeResultsWithDays(7) // デフォルト7日
}

// ListRuntimeResultsWithDays retrieves runtime scan results for specified days
func (c *Client) ListRuntimeResultsWithDays(days int) ([]ScanResult, error) {
	// Calculate date range
	endTime := time.Now()
	startTime := endTime.AddDate(0, 0, -days)

	endpoint := fmt.Sprintf("/runtime-results?from=%s&to=%s",
		startTime.Format("2006-01-02T15:04:05Z"),
		endTime.Format("2006-01-02T15:04:05Z"))

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

	return scanResp.Data, nil
}

// GetScanResultDetails retrieves detailed vulnerability information for a specific scan result
func (c *Client) GetScanResultDetails(resultID string) (*DetailedScanResponse, error) {
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

	var detailResp DetailedScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&detailResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &detailResp, nil
}

// GetScanResultDetailsV1Beta1 retrieves detailed vulnerability information using v1beta1 endpoint with enhanced fields
func (c *Client) GetScanResultDetailsV1Beta1(resultID string) (*DetailedScanResponseV1Beta1, error) {
	// Use v1beta1 endpoint directly
	apiURL := strings.Replace(c.baseURL, "us2.app.sysdig.com", "api.us2.sysdig.com", 1)
	if strings.Contains(c.baseURL, "localhost") {
		apiURL = c.baseURL
	}

	endpoint := fmt.Sprintf("/results/%s", resultID)
	url := fmt.Sprintf("%s/secure/vulnerability/v1beta1%s", apiURL, endpoint)

	req, err := http.NewRequest("GET", url, nil)
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
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("scan result not found: %s", resultID)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var detailResp DetailedScanResponseV1Beta1
	if err := json.NewDecoder(resp.Body).Decode(&detailResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &detailResp, nil
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
func (c *Client) GetAllVulnPackagesV2(resultID string) ([]VulnPackageV2, error) {
	var allVulnPackages []VulnPackageV2
	limit := 100
	offset := 0

	for {
		resp, err := c.GetVulnPackagesV2(resultID, limit, offset, "vulnSeverity", "desc")
		if err != nil {
			return nil, fmt.Errorf("failed to get vulnerability packages at offset %d: %w", offset, err)
		}

		allVulnPackages = append(allVulnPackages, resp.Data...)

		// Check if we've retrieved all data
		if len(resp.Data) < limit || offset + len(resp.Data) >= resp.Page.Matched {
			break
		}

		offset += limit
	}

	return allVulnPackages, nil
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
