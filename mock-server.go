package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type Vulnerability struct {
	ID               string                 `json:"id"`
	CVE              string                 `json:"cve"`
	Severity         string                 `json:"severity"`
	Status           string                 `json:"status"`
	Description      string                 `json:"description"`
	Packages         []string               `json:"packages"`
	Score            float64                `json:"score"`
	Vector           string                 `json:"vector"`
	PublishedAt      string                 `json:"publishedAt"`
	UpdatedAt        string                 `json:"updatedAt"`
	Fixable          bool                   `json:"fixable"`
	Exploitable      bool                   `json:"exploitable"`
	FixedVersion     string                 `json:"fixedVersion"`
	DetectionSources []DetectionSource      `json:"detectionSources"`
	AWSResources     []AWSResource          `json:"awsResources"`
	ContainerInfo    *ContainerInfo         `json:"containerInfo"`
	Metadata         map[string]interface{} `json:"metadata"`
}

type DetectionSource struct {
	Type        string `json:"type"`
	Location    string `json:"location"`
	ClusterName string `json:"clusterName"`
	Namespace   string `json:"namespace"`
	PodName     string `json:"podName"`
}

type AWSResource struct {
	AccountID    string `json:"accountId"`
	Region       string `json:"region"`
	ResourceType string `json:"resourceType"`
	ResourceID   string `json:"resourceId"`
	ResourceName string `json:"resourceName"`
	InstanceID   string `json:"instanceId"`
	ClusterArn   string `json:"clusterArn"`
	FunctionArn  string `json:"functionArn"`
}

type ContainerInfo struct {
	ImageName   string `json:"imageName"`
	ImageTag    string `json:"imageTag"`
	ImageID     string `json:"imageId"`
	Registry    string `json:"registry"`
	ImageDigest string `json:"imageDigest"`
}

type VulnerabilityResponse struct {
	Data       []Vulnerability `json:"data"`
	Page       int             `json:"page"`
	TotalPages int             `json:"totalPages"`
	Total      int             `json:"total"`
}

type ScanResultsResponse struct {
	Data []ScanResult `json:"data"`
}

type ScanResult struct {
	ResultID            string                 `json:"resultId"`
	CreatedAt           string                 `json:"createdAt"`
	PullString          string                 `json:"pullString,omitempty"`
	Scope               map[string]interface{} `json:"scope,omitempty"`
	VulnTotalBySeverity VulnSeverityCount      `json:"vulnTotalBySeverity"`
}

type VulnSeverityCount struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type DetailedScanResponse struct {
	Metadata        ScanMetadata           `json:"metadata"`
	Vulnerabilities map[string]VulnDetail  `json:"vulnerabilities"`
	Packages        map[string]PackageInfo `json:"packages"`
	RiskAccepts     map[string]interface{} `json:"riskAccepts"`
}

type ScanMetadata struct {
	PullString string `json:"pullString,omitempty"`
}

type VulnDetail struct {
	Name           string `json:"name"`
	Severity       string `json:"severity"`
	DisclosureDate string `json:"disclosureDate"`
	PackageRef     string `json:"packageRef"`
}

type PackageInfo struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

func main() {
	http.HandleFunc("/secure/vulnerability/v1/vulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		// Check authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Parse query parameters
		query := r.URL.Query()
		severity := query.Get("severity")
		fixable := query.Get("fixable")
		exploitable := query.Get("exploitable")

		// Generate mock vulnerabilities
		vulnerabilities := generateMockVulnerabilities()

		// Apply filters
		filtered := []Vulnerability{}
		for _, vuln := range vulnerabilities {
			// Severity filter
			if severity != "" && vuln.Severity != severity {
				continue
			}
			// Fixable filter
			if fixable == "true" && !vuln.Fixable {
				continue
			}
			// Exploitable filter
			if exploitable == "true" && !vuln.Exploitable {
				continue
			}
			filtered = append(filtered, vuln)
		}

		// Create response
		response := VulnerabilityResponse{
			Data:       filtered,
			Page:       1,
			TotalPages: 1,
			Total:      len(filtered),
		}

		// Send response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Handle specific vulnerability
	http.HandleFunc("/secure/vulnerability/v1/vulnerabilities/", func(w http.ResponseWriter, r *http.Request) {
		vulnID := r.URL.Path[len("/secure/vulnerability/v1/vulnerabilities/"):]
		if vulnID == "" {
			http.NotFound(w, r)
			return
		}

		// Return a specific vulnerability
		vuln := Vulnerability{
			ID:          vulnID,
			CVE:         vulnID,
			Severity:    "high",
			Status:      "open",
			Description: fmt.Sprintf("Detailed information for %s", vulnID),
			Score:       8.5,
			Fixable:     true,
			Exploitable: true,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(vuln)
	})

	// Handle pipeline results
	http.HandleFunc("/secure/vulnerability/v1/pipeline-results", func(w http.ResponseWriter, r *http.Request) {
		// Check authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		response := ScanResultsResponse{
			Data: generateMockPipelineResults(),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Handle runtime results
	http.HandleFunc("/secure/vulnerability/v1/runtime-results", func(w http.ResponseWriter, r *http.Request) {
		// Check authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		response := ScanResultsResponse{
			Data: generateMockRuntimeResults(),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Handle scan result details
	http.HandleFunc("/secure/vulnerability/v1/results/", func(w http.ResponseWriter, r *http.Request) {
		resultID := r.URL.Path[len("/secure/vulnerability/v1/results/"):]
		if resultID == "" {
			http.NotFound(w, r)
			return
		}

		// Check authorization header (but accept any non-empty token for mock)
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"message": "cannot verify credentials"})
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Return detailed scan result
		details := generateMockScanDetails(resultID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(details)
	})

	fmt.Println("Mock Sysdig API server starting on http://localhost:8081")
	fmt.Println("Use http://localhost:8081 as your API URL")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func generateMockVulnerabilities() []Vulnerability {
	now := time.Now()

	return []Vulnerability{
		{
			ID:           "CVE-2024-0001",
			CVE:          "CVE-2024-0001",
			Severity:     "critical",
			Status:       "open",
			Description:  "Critical remote code execution vulnerability in OpenSSL",
			Packages:     []string{"openssl", "libssl1.1"},
			Score:        9.8,
			Vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			PublishedAt:  now.AddDate(0, -1, 0).Format(time.RFC3339),
			UpdatedAt:    now.Format(time.RFC3339),
			Fixable:      true,
			Exploitable:  true,
			FixedVersion: "1.1.1w",
			DetectionSources: []DetectionSource{
				{Type: "runtime", Location: "prod-cluster", ClusterName: "eks-prod", Namespace: "default"},
				{Type: "image_repo", Location: "ecr.amazonaws.com/myapp"},
			},
			AWSResources: []AWSResource{
				{
					AccountID:    "123456789012",
					Region:       "us-east-1",
					ResourceType: "EKS",
					ResourceID:   "cluster-prod-1",
					ResourceName: "prod-cluster",
					ClusterArn:   "arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster",
				},
			},
			ContainerInfo: &ContainerInfo{
				ImageName: "myapp",
				ImageTag:  "v1.2.3",
				Registry:  "123456789012.dkr.ecr.us-east-1.amazonaws.com",
			},
		},
		{
			ID:           "CVE-2024-0002",
			CVE:          "CVE-2024-0002",
			Severity:     "high",
			Status:       "open",
			Description:  "SQL injection vulnerability in application framework",
			Packages:     []string{"django", "python3-django"},
			Score:        8.8,
			Vector:       "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			PublishedAt:  now.AddDate(0, -2, 0).Format(time.RFC3339),
			UpdatedAt:    now.AddDate(0, -1, 0).Format(time.RFC3339),
			Fixable:      true,
			Exploitable:  true,
			FixedVersion: "4.2.8",
			DetectionSources: []DetectionSource{
				{Type: "container", Location: "webapp-deployment", ClusterName: "eks-prod", Namespace: "webapp"},
			},
			AWSResources: []AWSResource{
				{
					AccountID:    "123456789012",
					Region:       "us-west-2",
					ResourceType: "Lambda",
					ResourceID:   "api-handler",
					ResourceName: "api-handler",
					FunctionArn:  "arn:aws:lambda:us-west-2:123456789012:function:api-handler",
				},
			},
			ContainerInfo: &ContainerInfo{
				ImageName: "webapp",
				ImageTag:  "latest",
				Registry:  "dockerhub.io",
			},
		},
		{
			ID:           "CVE-2024-0003",
			CVE:          "CVE-2024-0003",
			Severity:     "critical",
			Status:       "open",
			Description:  "Buffer overflow in image processing library",
			Packages:     []string{"imagemagick", "libmagickcore"},
			Score:        9.1,
			Vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
			PublishedAt:  now.AddDate(0, 0, -7).Format(time.RFC3339),
			UpdatedAt:    now.AddDate(0, 0, -1).Format(time.RFC3339),
			Fixable:      false,
			Exploitable:  true,
			FixedVersion: "",
			DetectionSources: []DetectionSource{
				{Type: "runtime", Location: "image-processor", ClusterName: "ecs-cluster"},
			},
			AWSResources: []AWSResource{
				{
					AccountID:    "987654321098",
					Region:       "eu-west-1",
					ResourceType: "ECS",
					ResourceID:   "image-service",
					ResourceName: "image-processor-service",
					ClusterArn:   "arn:aws:ecs:eu-west-1:987654321098:cluster/production",
				},
			},
			ContainerInfo: &ContainerInfo{
				ImageName: "image-processor",
				ImageTag:  "v2.1.0",
				Registry:  "987654321098.dkr.ecr.eu-west-1.amazonaws.com",
			},
		},
		{
			ID:           "CVE-2024-0004",
			CVE:          "CVE-2024-0004",
			Severity:     "medium",
			Status:       "open",
			Description:  "Information disclosure in logging library",
			Packages:     []string{"log4j", "log4j-core"},
			Score:        5.3,
			Vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
			PublishedAt:  now.AddDate(0, -3, 0).Format(time.RFC3339),
			UpdatedAt:    now.AddDate(0, -2, 0).Format(time.RFC3339),
			Fixable:      true,
			Exploitable:  false,
			FixedVersion: "2.20.0",
			DetectionSources: []DetectionSource{
				{Type: "image_repo", Location: "gcr.io/project/backend"},
			},
			AWSResources: []AWSResource{
				{
					AccountID:    "111222333444",
					Region:       "ap-northeast-1",
					ResourceType: "EC2",
					ResourceID:   "i-0123456789abcdef",
					ResourceName: "backend-server-01",
					InstanceID:   "i-0123456789abcdef",
				},
			},
			ContainerInfo: &ContainerInfo{
				ImageName: "backend-service",
				ImageTag:  "v3.4.5",
				Registry:  "gcr.io",
			},
		},
		{
			ID:           "CVE-2024-0005",
			CVE:          "CVE-2024-0005",
			Severity:     "high",
			Status:       "open",
			Description:  "Authentication bypass in web framework",
			Packages:     []string{"spring-security", "spring-core"},
			Score:        7.5,
			Vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			PublishedAt:  now.AddDate(0, 0, -14).Format(time.RFC3339),
			UpdatedAt:    now.AddDate(0, 0, -7).Format(time.RFC3339),
			Fixable:      true,
			Exploitable:  false,
			FixedVersion: "5.8.9",
			DetectionSources: []DetectionSource{
				{Type: "runtime", Location: "api-gateway", ClusterName: "k8s-prod"},
				{Type: "container", Location: "auth-service", ClusterName: "k8s-prod"},
			},
			AWSResources: []AWSResource{
				{
					AccountID:    "555666777888",
					Region:       "us-east-2",
					ResourceType: "ECR",
					ResourceID:   "auth-service-repo",
					ResourceName: "auth-service",
				},
			},
			ContainerInfo: &ContainerInfo{
				ImageName: "auth-service",
				ImageTag:  "v1.0.0",
				Registry:  "555666777888.dkr.ecr.us-east-2.amazonaws.com",
			},
		},
	}
}

func generateMockPipelineResults() []ScanResult {
	now := time.Now()
	return []ScanResult{
		{
			ResultID:  "1869155e041f0e21e93a2a19e8a5c3c9",
			CreatedAt: now.AddDate(0, 0, -1).Format("2006-01-02T15:04:05Z"),
			PullString: "123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/myapp:latest",
			VulnTotalBySeverity: VulnSeverityCount{
				Critical: 3,
				High:     5,
				Medium:   12,
				Low:      8,
			},
		},
		{
			ResultID:  "2b7c2da4b8e5f1234567890abcdef123",
			CreatedAt: now.AddDate(0, 0, -2).Format("2006-01-02T15:04:05Z"),
			PullString: "987654321098.dkr.ecr.ap-northeast-1.amazonaws.com/webapp:v1.2.3",
			VulnTotalBySeverity: VulnSeverityCount{
				Critical: 1,
				High:     3,
				Medium:   7,
				Low:      15,
			},
		},
	}
}

func generateMockRuntimeResults() []ScanResult {
	now := time.Now()
	return []ScanResult{
		{
			ResultID:  "runtime-123456789abcdef0123456789abcdef0",
			CreatedAt: now.AddDate(0, 0, -1).Format("2006-01-02T15:04:05Z"),
			Scope: map[string]interface{}{
				"aws.account.name": "prod-account",
				"aws.ecs.cluster.name": "production-cluster",
				"aws.ecs.task.container.name": "web-app",
			},
			VulnTotalBySeverity: VulnSeverityCount{
				Critical: 2,
				High:     7,
				Medium:   15,
				Low:      23,
			},
		},
		{
			ResultID:  "runtime-987654321fedcba0987654321fedcba0",
			CreatedAt: now.AddDate(0, 0, -3).Format("2006-01-02T15:04:05Z"),
			Scope: map[string]interface{}{
				"aws.account.name": "staging-account",
				"aws.lambda.name": "api-handler",
			},
			VulnTotalBySeverity: VulnSeverityCount{
				Critical: 0,
				High:     2,
				Medium:   5,
				Low:      10,
			},
		},
	}
}

func generateMockScanDetails(resultID string) DetailedScanResponse {
	now := time.Now()
	return DetailedScanResponse{
		Metadata: ScanMetadata{
			PullString: "123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/myapp:latest",
		},
		Vulnerabilities: map[string]VulnDetail{
			"vuln1": {
				Name:           "CVE-2024-0001",
				Severity:       "critical",
				DisclosureDate: now.AddDate(0, -1, 0).Format("2006-01-02"),
				PackageRef:     "pkg1",
			},
			"vuln2": {
				Name:           "CVE-2024-0002",
				Severity:       "high",
				DisclosureDate: now.AddDate(0, -2, 0).Format("2006-01-02"),
				PackageRef:     "pkg2",
			},
			"vuln3": {
				Name:           "CVE-2024-0003",
				Severity:       "medium",
				DisclosureDate: now.AddDate(0, -3, 0).Format("2006-01-02"),
				PackageRef:     "pkg1",
			},
		},
		Packages: map[string]PackageInfo{
			"pkg1": {
				Name: "openssl",
				Path: "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
			},
			"pkg2": {
				Name: "nginx",
				Path: "/usr/sbin/nginx",
			},
		},
		RiskAccepts: make(map[string]interface{}),
	}
}