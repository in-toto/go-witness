// Copyright 2025 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package secretscan

import (
	"fmt"
	"os"
	"regexp"

	"github.com/in-toto/go-witness/log"
	"github.com/spf13/viper"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// initGitleaksDetector creates and configures a Gitleaks detector
// It supports either:
// 1. Loading a custom configuration from a TOML file via configPath, or
// 2. Using default configuration with optional allowlist settings
func (a *Attestor) initGitleaksDetector() (*detect.Detector, error) {
	var detector *detect.Detector
	var err error

	if a.configPath != "" {
		detector, err = a.loadCustomGitleaksConfig()
	} else {
		detector, err = a.createDefaultGitleaksConfig()
	}

	if err != nil {
		return nil, err
	}

	// Apply file size limit configuration regardless of config source
	if detector != nil && a.maxFileSizeMB > 0 {
		detector.MaxTargetMegaBytes = a.maxFileSizeMB
	}

	return detector, nil
}

// loadCustomGitleaksConfig creates a detector using a custom TOML configuration file
func (a *Attestor) loadCustomGitleaksConfig() (*detect.Detector, error) {
	log.Debugf("(attestation/secretscan) loading gitleaks configuration from: %s", a.configPath)

	// Create a new Viper instance to avoid interfering with global state
	v := viper.New()
	v.SetConfigFile(a.configPath)

	// Attempt to read the config file
	if err := v.ReadInConfig(); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("gitleaks config file not found at %s: %w", a.configPath, err)
		}
		return nil, fmt.Errorf("error reading gitleaks config file %s: %w", a.configPath, err)
	}

	// Parse the configuration into ViperConfig struct
	var viperConfig config.ViperConfig
	if err := v.Unmarshal(&viperConfig); err != nil {
		return nil, fmt.Errorf("error unmarshaling gitleaks config from %s: %w", a.configPath, err)
	}

	// Convert ViperConfig to Gitleaks internal config.Config format
	cfg, err := viperConfig.Translate()
	if err != nil {
		return nil, fmt.Errorf("error translating gitleaks config from %s: %w", a.configPath, err)
	}

	// Warn if no rules were loaded, but continue since Gitleaks might use defaults
	if len(cfg.Rules) == 0 {
		log.Warnf("(attestation/secretscan) gitleaks config from %s contains no rules", a.configPath)
	}

	// Create detector using the loaded config
	detector := detect.NewDetector(cfg)
	log.Infof("(attestation/secretscan) using custom gitleaks config from %s (command-line allowlists ignored)", a.configPath)

	return detector, nil
}

// createDefaultGitleaksConfig creates a detector with default configuration
// and applies allowlist settings if provided
func (a *Attestor) createDefaultGitleaksConfig() (*detect.Detector, error) {
	log.Debugf("(attestation/secretscan) using default gitleaks configuration")

	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("error creating default gitleaks detector: %w", err)
	}

	// Apply manual allowlists if provided
	if a.allowList != nil {
		if err := a.mergeAllowlistIntoGitleaksConfig(detector); err != nil {
			log.Warnf("(attestation/secretscan) error merging allowlist: %s", err)
			// Continue even if there was an error merging allowlists
		}
	}

	return detector, nil
}

// mergeAllowlistIntoGitleaksConfig applies the attestor's allowlist settings to the detector
// This is only used when no custom config file is provided
func (a *Attestor) mergeAllowlistIntoGitleaksConfig(detector *detect.Detector) error {
	// Validate and compile the regexes
	validatedPatterns, err := a.compileRegexes(a.allowList.Regexes)
	if err != nil {
		return fmt.Errorf("error validating allowlist regexes: %w", err)
	}

	// Add regexes to the detector's allowlist description
	for _, pattern := range validatedPatterns {
		detector.Config.Allowlist.Description = fmt.Sprintf("%s\nRegex: %s",
			detector.Config.Allowlist.Description, pattern)
		log.Debugf("(attestation/secretscan) added allowlist regex: %s", pattern)
	}

	// Add stop words to the detector's allowlist description
	for _, stopWord := range a.allowList.StopWords {
		detector.Config.Allowlist.Description = fmt.Sprintf("%s\nStop word: %s",
			detector.Config.Allowlist.Description, stopWord)
		log.Debugf("(attestation/secretscan) added allowlist stop word: %s", stopWord)
	}

	// Add paths to the detector's allowlist description
	for _, path := range a.allowList.Paths {
		detector.Config.Allowlist.Description = fmt.Sprintf("%s\nPath: %s",
			detector.Config.Allowlist.Description, path)
		log.Debugf("(attestation/secretscan) added allowlist path: %s", path)
	}

	return nil
}

// compileRegexes validates and compiles a list of regex patterns
// It returns a map of pattern string to compiled pattern object
func (a *Attestor) compileRegexes(patterns []string) (map[string]*regexp.Regexp, error) {
	result := make(map[string]*regexp.Regexp)
	for _, pattern := range patterns {
		compiledRegex, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern %q: %w", pattern, err)
		}
		result[pattern] = compiledRegex
	}
	return result, nil
}
