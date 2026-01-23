package main

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

func TestGetEnvStr(t *testing.T) {
	tests := []struct {
		name         string
		envKey       string
		envValue     string
		defaultValue string
		expected     string
	}{
		{
			name:         "returns default when env not set",
			envKey:       "TEST_UNSET_VAR",
			envValue:     "",
			defaultValue: "default",
			expected:     "default",
		},
		{
			name:         "returns env value when set",
			envKey:       "TEST_SET_VAR",
			envValue:     "custom",
			defaultValue: "default",
			expected:     "custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up env before and after test
			os.Unsetenv(tt.envKey)
			defer os.Unsetenv(tt.envKey)

			if tt.envValue != "" {
				os.Setenv(tt.envKey, tt.envValue)
			}

			result := getEnvStr(tt.envKey, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("getEnvStr(%q) = %q, want %q", tt.envKey, result, tt.expected)
			}
		})
	}
}

func TestGetEnvInt(t *testing.T) {
	tests := []struct {
		name         string
		envKey       string
		envValue     string
		defaultValue int
		expected     int
	}{
		{
			name:         "returns default when env not set",
			envKey:       "TEST_INT_UNSET",
			envValue:     "",
			defaultValue: 42,
			expected:     42,
		},
		{
			name:         "returns parsed int when valid",
			envKey:       "TEST_INT_VALID",
			envValue:     "100",
			defaultValue: 42,
			expected:     100,
		},
		{
			name:         "returns default when invalid int",
			envKey:       "TEST_INT_INVALID",
			envValue:     "not-a-number",
			defaultValue: 42,
			expected:     42,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv(tt.envKey)
			defer os.Unsetenv(tt.envKey)

			if tt.envValue != "" {
				os.Setenv(tt.envKey, tt.envValue)
			}

			result := getEnvInt(tt.envKey, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("getEnvInt(%q) = %d, want %d", tt.envKey, result, tt.expected)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	// Save original env and restore after test
	originalPort := os.Getenv(EnvPort)
	originalLogLevel := os.Getenv(EnvLogLevel)
	defer func() {
		os.Setenv(EnvPort, originalPort)
		os.Setenv(EnvLogLevel, originalLogLevel)
	}()

	t.Run("loads defaults when env not set", func(t *testing.T) {
		// Clear relevant env vars
		os.Unsetenv(EnvPort)
		os.Unsetenv(EnvLogLevel)

		config := LoadConfig()

		if config.Port != DefaultPort {
			t.Errorf("Port = %q, want %q", config.Port, DefaultPort)
		}
		if config.DebugMode != false {
			t.Errorf("DebugMode = %v, want false", config.DebugMode)
		}
		if config.RulesPath != DefaultRulesPath {
			t.Errorf("RulesPath = %q, want %q", config.RulesPath, DefaultRulesPath)
		}
	})

	t.Run("loads custom values from env", func(t *testing.T) {
		os.Setenv(EnvPort, "8080")
		os.Setenv(EnvLogLevel, "debug")

		config := LoadConfig()

		if config.Port != "8080" {
			t.Errorf("Port = %q, want %q", config.Port, "8080")
		}
		if config.DebugMode != true {
			t.Errorf("DebugMode = %v, want true", config.DebugMode)
		}
	})

	t.Run("calculates byte sizes correctly", func(t *testing.T) {
		os.Unsetenv(EnvMaxUploadSize)
		os.Unsetenv(EnvMaxExtractedSize)

		config := LoadConfig()

		// 512 MB in bytes
		expectedUploadSize := int64(512) << 20
		if config.MaxUploadSize != expectedUploadSize {
			t.Errorf("MaxUploadSize = %d, want %d", config.MaxUploadSize, expectedUploadSize)
		}

		// 1024 MB in bytes
		expectedExtractedSize := int64(1024) << 20
		if config.MaxExtractedSize != expectedExtractedSize {
			t.Errorf("MaxExtractedSize = %d, want %d", config.MaxExtractedSize, expectedExtractedSize)
		}
	})

	t.Run("sets timeouts correctly", func(t *testing.T) {
		os.Unsetenv(EnvReadTimeout)
		os.Unsetenv(EnvScanTimeout)

		config := LoadConfig()

		expectedReadTimeout := time.Duration(DefaultReadTimeoutSecs) * time.Second
		if config.ReadTimeout != expectedReadTimeout {
			t.Errorf("ReadTimeout = %v, want %v", config.ReadTimeout, expectedReadTimeout)
		}

		expectedScanTimeout := time.Duration(DefaultScanTimeoutMins) * time.Minute
		if config.ScanTimeout != expectedScanTimeout {
			t.Errorf("ScanTimeout = %v, want %v", config.ScanTimeout, expectedScanTimeout)
		}
	})
}

func TestLogConfig(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	cfg := &Config{
		Port:              "9001",
		DebugMode:         true,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      300 * time.Second,
		IdleTimeout:       120 * time.Second,
		RulesPath:         "/rules",
		MaxUploadSize:     512 << 20,
		MaxExtractedSize:  1024 << 20,
		MaxFileCount:      100000,
		MaxSingleFileSize: 256 << 20,
		ScanTimeout:       5 * time.Minute,
	}

	cfg.LogConfig()

	output := buf.String()

	// Verify key config values are logged
	if !strings.Contains(output, "9001") {
		t.Error("LogConfig should log port")
	}
	if !strings.Contains(output, "true") {
		t.Error("LogConfig should log debug mode")
	}
	if !strings.Contains(output, "/rules") {
		t.Error("LogConfig should log rules path")
	}
	if !strings.Contains(output, "512") {
		t.Error("LogConfig should log max upload size")
	}
}
