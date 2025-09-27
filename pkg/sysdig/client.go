package sysdig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	ID          string                 `json:"id"`
	CVE         string                 `json:"cve,omitempty"`
	Severity    string                 `json:"severity"`
	Status      string                 `json:"status"`
	Description string                 `json:"description"`
	Packages    []string               `json:"packages,omitempty"`
	Score       float64                `json:"score,omitempty"`
	Vector      string                 `json:"vector,omitempty"`
	PublishedAt string                 `json:"publishedAt,omitempty"`
	UpdatedAt   string                 `json:"updatedAt,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// VulnerabilityResponse represents the API response for vulnerability lists
type VulnerabilityResponse struct {
	Data       []Vulnerability `json:"data"`
	Page       int             `json:"page"`
	TotalPages int             `json:"totalPages"`
	Total      int             `json:"total"`
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
	url := fmt.Sprintf("%s/api/secure/v1%s", c.baseURL, endpoint)

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
	req.Header.Set("User-Agent", "sysdig-vuls-utils/1.0.0")

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
