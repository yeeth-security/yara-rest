package main

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all service configuration.
// All settings can be overridden via environment variables.
type Config struct {
	// Server settings
	Port      string
	DebugMode bool

	// HTTP server timeouts (prevents slowloris and resource exhaustion)
	ReadTimeout  time.Duration // Max time to read entire request including body
	WriteTimeout time.Duration // Max time to write response
	IdleTimeout  time.Duration // Max time for keep-alive connections

	// YARA-X settings
	RulesPath string

	// Upload limits
	MaxUploadSize int64 // Maximum upload size for multipart form (bytes)

	// Zip bomb protection limits
	MaxExtractedSize  int64  // Maximum total size of extracted files (bytes)
	MaxFileCount      int    // Maximum number of files in archive
	MaxSingleFileSize uint64 // Maximum size of single file (bytes)

	// Scan settings
	ScanTimeout  time.Duration // Maximum time for scan operation
	MaxScanDepth int           // Max directory recursion depth (0 = unlimited)
}

// Environment variable names
const (
	EnvPort             = "PORT"
	EnvLogLevel         = "LOG_LEVEL"
	EnvMaxExtractedSize = "MAX_EXTRACTED_SIZE_MB"
	EnvMaxFileCount     = "MAX_FILE_COUNT"
	EnvMaxSingleFile    = "MAX_SINGLE_FILE_MB"
	EnvMaxUploadSize    = "MAX_UPLOAD_SIZE_MB"
	EnvScanTimeout      = "SCAN_TIMEOUT_MINUTES"
	EnvMaxScanDepth     = "MAX_RECURSION"

	// HTTP server timeouts
	EnvReadTimeout  = "HTTP_READ_TIMEOUT_SECONDS"
	EnvWriteTimeout = "HTTP_WRITE_TIMEOUT_SECONDS"
	EnvIdleTimeout  = "HTTP_IDLE_TIMEOUT_SECONDS"

	// YARA-X settings
	EnvRulesPath = "YARA_RULES_PATH"
)

// Default values
const (
	DefaultPort            = "9001"
	DefaultRulesPath       = "/rules"
	DefaultMaxExtractedMB  = 1024   // 1GB
	DefaultMaxFileCount    = 100000 // 100k files
	DefaultMaxSingleFileMB = 256    // 256MB
	DefaultMaxUploadMB     = 512    // 512MB max upload size
	DefaultScanTimeoutMins = 5      // 5 minutes
	DefaultMaxScanDepth    = 0      // 0 = unlimited recursion

	// HTTP server timeout defaults (in seconds)
	DefaultReadTimeoutSecs  = 60  // 1 minute to read request
	DefaultWriteTimeoutSecs = 300 // 5 minutes for large scan responses
	DefaultIdleTimeoutSecs  = 120 // 2 minutes for keep-alive
)

// LoadConfig loads configuration from environment variables.
// Uses sensible defaults if not specified.
func LoadConfig() *Config {
	config := &Config{
		// Server settings
		Port:      getEnvStr(EnvPort, DefaultPort),
		DebugMode: strings.ToLower(os.Getenv(EnvLogLevel)) == "debug",

		// HTTP server timeouts
		ReadTimeout:  time.Duration(getEnvInt(EnvReadTimeout, DefaultReadTimeoutSecs)) * time.Second,
		WriteTimeout: time.Duration(getEnvInt(EnvWriteTimeout, DefaultWriteTimeoutSecs)) * time.Second,
		IdleTimeout:  time.Duration(getEnvInt(EnvIdleTimeout, DefaultIdleTimeoutSecs)) * time.Second,

		// YARA-X settings
		RulesPath: getEnvStr(EnvRulesPath, DefaultRulesPath),

		// Upload limits
		MaxUploadSize: int64(getEnvInt(EnvMaxUploadSize, DefaultMaxUploadMB)) << 20,

		// Zip bomb protection
		MaxExtractedSize:  int64(getEnvInt(EnvMaxExtractedSize, DefaultMaxExtractedMB)) << 20,
		MaxFileCount:      getEnvInt(EnvMaxFileCount, DefaultMaxFileCount),
		MaxSingleFileSize: uint64(getEnvInt(EnvMaxSingleFile, DefaultMaxSingleFileMB)) << 20,

		// Scan settings
		ScanTimeout:  time.Duration(getEnvInt(EnvScanTimeout, DefaultScanTimeoutMins)) * time.Minute,
		MaxScanDepth: getEnvInt(EnvMaxScanDepth, DefaultMaxScanDepth),
	}

	return config
}

// LogConfig logs the current configuration (useful for debugging)
func (c *Config) LogConfig() {
	log.Printf("Configuration:")
	log.Printf("  Port: %s", c.Port)
	log.Printf("  Debug mode: %v", c.DebugMode)
	log.Printf("  HTTP read timeout: %v", c.ReadTimeout)
	log.Printf("  HTTP write timeout: %v", c.WriteTimeout)
	log.Printf("  HTTP idle timeout: %v", c.IdleTimeout)
	log.Printf("  Rules path: %s", c.RulesPath)
	log.Printf("  Max upload size: %d MB", c.MaxUploadSize>>20)
	log.Printf("  Max extracted size: %d MB", c.MaxExtractedSize>>20)
	log.Printf("  Max file count: %d", c.MaxFileCount)
	log.Printf("  Max single file: %d MB", c.MaxSingleFileSize>>20)
	log.Printf("  Scan timeout: %v", c.ScanTimeout)
	if c.MaxScanDepth == 0 {
		log.Printf("  Max scan depth: unlimited")
	} else {
		log.Printf("  Max scan depth: %d", c.MaxScanDepth)
	}
}

// getEnvStr returns environment variable value or default
func getEnvStr(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt returns environment variable as int or default
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
		log.Printf("Warning: invalid value for %s, using default %d", key, defaultValue)
	}
	return defaultValue
}
