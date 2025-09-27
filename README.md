# sysdig-vuls-utils

**Sysdig Vulnerability API Tool-set**

A Golang-based command-line tool and library for interacting with Sysdig's vulnerability management API. This tool allows you to list, retrieve, and manage vulnerabilities in your Sysdig Cloud environment.

## Features

- **List Vulnerabilities**: Retrieve all vulnerabilities from your Sysdig environment
- **Get Vulnerability Details**: Fetch detailed information about specific vulnerabilities
- **Update Vulnerabilities**: Modify vulnerability status and metadata
- **Filter by Severity**: Query vulnerabilities by severity level (critical, high, medium, low)
- **Filter by Package**: Find vulnerabilities affecting specific packages
- **Configuration Management**: Support for config files, environment variables, and CLI flags
- **JSON Output**: Machine-readable output for integration with other tools

## Installation

### Prerequisites

- Go 1.19 or later
- Valid Sysdig API token

### Build from Source

```bash
git clone https://github.com/kaz-under-the-bridge/sysdig-vuls-utils.git
cd sysdig-vuls-utils
go build -o sysdig-vuls cmd/sysdig-vuls/main.go
```

### Install with Go

```bash
go install github.com/kaz-under-the-bridge/sysdig-vuls-utils/cmd/sysdig-vuls@latest
```

## Configuration

### API Token

You need a valid Sysdig API token to use this tool. You can obtain one from:
- **Sysdig US2**: https://us2.app.sysdig.com/secure/settings/user
- **Sysdig EU**: https://eu1.app.sysdig.com/secure/settings/user

### Configuration Options

The tool supports multiple ways to configure the API token and endpoint:

1. **Command Line Flags** (highest priority)
2. **Configuration File** (JSON format)
3. **Environment Variables**
4. **Default Values** (lowest priority)

#### Environment Variables

```bash
export SYSDIG_API_TOKEN="your_api_token_here"
export SYSDIG_API_URL="https://us2.app.sysdig.com"  # Optional, defaults to US2
```

#### Configuration File

Create a JSON configuration file (see `examples/config.json`):

```json
{
  "api_token": "your_api_token_here",
  "api_url": "https://us2.app.sysdig.com"
}
```

## Usage

### Command Line Interface

```bash
sysdig-vuls [options]
```

#### Options

- `-config string`: Path to configuration file
- `-token string`: Sysdig API token (or use SYSDIG_API_TOKEN environment variable)
- `-url string`: Sysdig API base URL (default: "https://us2.app.sysdig.com")
- `-command string`: Command to execute: list, get, update (default: "list")
- `-id string`: Vulnerability ID (required for get/update commands)
- `-help`: Show help message
- `-version`: Show version information

### Examples

#### List All Vulnerabilities

```bash
# Using environment variable
export SYSDIG_API_TOKEN="your_token_here"
sysdig-vuls -command list

# Using command line flag
sysdig-vuls -token "your_token_here" -command list

# Using config file
sysdig-vuls -config config.json -command list
```

#### Get Specific Vulnerability

```bash
sysdig-vuls -token "your_token_here" -command get -id CVE-2023-1234
```

#### Update Vulnerability Status

```bash
sysdig-vuls -token "your_token_here" -command update -id CVE-2023-1234
```

## API Documentation

This tool is based on the Sysdig Secure API. For detailed API documentation, refer to:

- **Sysdig API Documentation**: https://us2.app.sysdig.com/apidocs/secure?_product=SDS
- **Swagger UI**: https://us2.app.sysdig.com/secure/swagger.html

### Supported API Endpoints

The tool currently supports the following Sysdig API endpoints:

#### Vulnerabilities

- `GET /api/secure/v1/vulnerabilities` - List all vulnerabilities
- `GET /api/secure/v1/vulnerabilities/{id}` - Get specific vulnerability
- `PATCH /api/secure/v1/vulnerabilities/{id}` - Update vulnerability
- `GET /api/secure/v1/vulnerabilities?severity={level}` - Filter by severity
- `GET /api/secure/v1/vulnerabilities?package={name}` - Filter by package

### API Response Format

```json
{
  "data": [
    {
      "id": "CVE-2023-1234",
      "cve": "CVE-2023-1234",
      "severity": "high",
      "status": "open",
      "description": "Vulnerability description",
      "packages": ["package1", "package2"],
      "score": 8.5,
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "publishedAt": "2023-01-01T00:00:00Z",
      "updatedAt": "2023-01-02T00:00:00Z",
      "metadata": {}
    }
  ],
  "page": 1,
  "totalPages": 10,
  "total": 250
}
```

## Library Usage

You can also use this tool as a Go library in your own projects:

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/kaz-under-the-bridge/sysdig-vuls-utils/pkg/sysdig"
)

func main() {
    client := sysdig.NewClient("https://us2.app.sysdig.com", "your_api_token")
    
    // List vulnerabilities
    vulns, err := client.ListVulnerabilities()
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Found %d vulnerabilities\n", len(vulns))
    
    // Get specific vulnerability
    vuln, err := client.GetVulnerability("CVE-2023-1234")
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Vulnerability: %s, Severity: %s\n", vuln.ID, vuln.Severity)
}
```

### Available Client Methods

- `ListVulnerabilities() ([]Vulnerability, error)`
- `GetVulnerability(vulnID string) (*Vulnerability, error)`
- `UpdateVulnerability(vulnID string, updates map[string]interface{}) error`
- `ListVulnerabilitiesByPackage(packageName string) ([]Vulnerability, error)`
- `ListVulnerabilitiesBySeverity(severity string) ([]Vulnerability, error)`

## Error Handling

The tool provides comprehensive error handling:

- **Authentication Errors**: Invalid or missing API tokens
- **Network Errors**: Connection issues or timeouts
- **API Errors**: Invalid requests or server errors
- **Not Found Errors**: When requesting non-existent vulnerabilities

## Regional Endpoints

Sysdig operates in multiple regions. Use the appropriate endpoint for your region:

- **US East (default)**: `https://us2.app.sysdig.com`
- **US West**: `https://us3.app.sysdig.com`
- **EU**: `https://eu1.app.sysdig.com`
- **Asia Pacific**: `https://au1.app.sysdig.com`

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For issues and questions:

1. Check the [GitHub Issues](https://github.com/kaz-under-the-bridge/sysdig-vuls-utils/issues)
2. Refer to the [Sysdig Documentation](https://docs.sysdig.com/)
3. Contact Sysdig Support for API-specific issues

## Changelog

### v1.0.0
- Initial release
- Basic vulnerability listing, retrieval, and update functionality
- Support for configuration files and environment variables
- CLI tool and Go library
