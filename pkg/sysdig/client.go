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
	// Use correct API base URL - api.us2.sysdig.com instead of us2.app.sysdig.com
	apiURL := strings.Replace(c.baseURL, "us2.app.sysdig.com", "api.us2.sysdig.com", 1)
	url := fmt.Sprintf("%s/secure/vulnerability/v1%s", apiURL, endpoint)

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
	req.Header.Set("Content-Type", "application/json")
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

// SysdigScanResult represents a scan result from Sysdig API
type SysdigScanResult struct {
	CreatedAt               string                            `json:"createdAt"`
	ImageID                 string                            `json:"imageId"`
	PolicyEvaluationResult  string                            `json:"policyEvaluationResult"`
	PullString              string                            `json:"pullString"`
	ResultID                string                            `json:"resultId"`
	VulnTotalBySeverity     map[string]int                    `json:"vulnTotalBySeverity"`
	Scope                   map[string]interface{}            `json:"scope,omitempty"` // For runtime results
}

// SysdigScanResponse represents the API response for scan results
type SysdigScanResponse struct {
	Data []SysdigScanResult `json:"data"`
}

// ListPipelineResults retrieves pipeline scan results
func (c *Client) ListPipelineResults() ([]SysdigScanResult, error) {
	resp, err := c.makeRequest("GET", "/pipeline-results", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var scanResp SysdigScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&scanResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return scanResp.Data, nil
}

// ListRuntimeResults retrieves runtime scan results
func (c *Client) ListRuntimeResults() ([]SysdigScanResult, error) {
	resp, err := c.makeRequest("GET", "/runtime-results", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var scanResp SysdigScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&scanResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return scanResp.Data, nil
}

// GetScanResultDetails retrieves detailed vulnerability information for a specific scan result
func (c *Client) GetScanResultDetails(resultID string) (*VulnerabilityResponse, error) {
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

	var vulnResp VulnerabilityResponse
	if err := json.NewDecoder(resp.Body).Decode(&vulnResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &vulnResp, nil
}
