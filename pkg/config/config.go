package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config holds the configuration for the Sysdig vulnerability tool
type Config struct {
	APIToken string `json:"api_token"`
	APIURL   string `json:"api_url"`
}

// Load configuration from file, command line flags, or environment variables
// Priority: command line flags > config file > environment variables > defaults
func Load(configFile, apiToken, apiURL string) (*Config, error) {
	cfg := &Config{
		APIURL: "https://us2.app.sysdig.com", // default
	}

	// Load from environment variables first
	if token := os.Getenv("SYSDIG_API_TOKEN"); token != "" {
		cfg.APIToken = token
	}
	if url := os.Getenv("SYSDIG_API_URL"); url != "" {
		cfg.APIURL = url
	}

	// Load from config file if provided
	if configFile != "" {
		fileConfig, err := loadFromFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load config file: %w", err)
		}
		if fileConfig.APIToken != "" {
			cfg.APIToken = fileConfig.APIToken
		}
		if fileConfig.APIURL != "" {
			cfg.APIURL = fileConfig.APIURL
		}
	}

	// Override with command line flags if provided
	if apiToken != "" {
		cfg.APIToken = apiToken
	}
	if apiURL != "" {
		cfg.APIURL = apiURL
	}

	return cfg, nil
}

func loadFromFile(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Save configuration to file
func (c *Config) Save(filename string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0600)
}
