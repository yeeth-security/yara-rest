package main

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func init() {
	// Initialize global config for tests
	config = &Config{
		Port:              "9001",
		DebugMode:         false,
		RulesPath:         "./test",
		MaxUploadSize:     10 << 20,
		MaxExtractedSize:  50 << 20,
		MaxFileCount:      100,
		MaxSingleFileSize: 5 << 20,
		ScanTimeout:       1 * time.Minute,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      300 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	scanner = NewScanner(config)
}

func TestHandleHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	handleHealth(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)

	if body["status"] != "ok" {
		t.Errorf("status = %v, want %q", body["status"], "ok")
	}

	if body["rules_path"] != config.RulesPath {
		t.Errorf("rules_path = %v, want %q", body["rules_path"], config.RulesPath)
	}
}

func TestHandleScanMethodNotAllowed(t *testing.T) {
	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/scan", nil)
			w := httptest.NewRecorder()

			handleScan(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func TestHandleScanNoFile(t *testing.T) {
	// Create request with empty multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/scan", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()

	handleScan(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp ScanResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.Error == "" {
		t.Error("expected error message in response")
	}
}

func TestHandleScanWithFile(t *testing.T) {
	// Skip if test rules directory doesn't exist
	if _, err := os.Stat("./test"); os.IsNotExist(err) {
		t.Skip("test rules directory not found")
	}

	// Skip if YARA-X binary not available (integration test)
	if _, err := os.Stat("/usr/local/bin/yr"); os.IsNotExist(err) {
		t.Skip("YARA-X binary not found - run in container for full test")
	}

	// Create multipart form with a test file
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatal(err)
	}
	part.Write([]byte("clean file content"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/scan", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()

	handleScan(w, req)

	// Should succeed (may or may not have matches depending on rules)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp ScanResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.Error != "" {
		t.Errorf("unexpected error: %s", resp.Error)
	}

	if resp.ScannedFiles != 1 {
		t.Errorf("scanned_files = %d, want 1", resp.ScannedFiles)
	}

	if resp.ScanTimeMs < 0 {
		t.Errorf("scan_time_ms = %d, should be >= 0", resp.ScanTimeMs)
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal filename",
			input:    "document.pdf",
			expected: "document.pdf",
		},
		{
			name:     "filename with spaces",
			input:    "my document.pdf",
			expected: "my document.pdf",
		},
		{
			name:     "removes newlines",
			input:    "file\nname.txt",
			expected: "file name.txt",
		},
		{
			name:     "removes carriage returns",
			input:    "file\rname.txt",
			expected: "file name.txt",
		},
		{
			name:     "removes CRLF",
			input:    "file\r\nname.txt",
			expected: "file  name.txt",
		},
		{
			name:     "removes control characters",
			input:    "file\x00\x01\x1fname.txt",
			expected: "filename.txt",
		},
		{
			name:     "preserves tabs",
			input:    "file\tname.txt",
			expected: "file\tname.txt",
		},
		{
			name:     "truncates long filenames",
			input:    strings.Repeat("a", 300),
			expected: strings.Repeat("a", 255) + "...",
		},
		{
			name:     "handles unicode",
			input:    "文件名.txt",
			expected: "文件名.txt",
		},
		{
			name:     "log injection attempt",
			input:    "file.txt\n[ERROR] Fake log entry",
			expected: "file.txt [ERROR] Fake log entry",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeFilename(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSendError(t *testing.T) {
	w := httptest.NewRecorder()

	sendError(w, "Test error message", http.StatusBadRequest)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	body, _ := io.ReadAll(resp.Body)
	var scanResp ScanResponse
	json.Unmarshal(body, &scanResp)

	if scanResp.Error != "Test error message" {
		t.Errorf("error = %q, want %q", scanResp.Error, "Test error message")
	}
}

func TestHandleScanInvalidContentType(t *testing.T) {
	// Send request with wrong content type
	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader("not multipart"))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()

	handleScan(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleScanEmptyFilename(t *testing.T) {
	// Skip if YARA-X not available
	if _, err := os.Stat("/usr/local/bin/yr"); os.IsNotExist(err) {
		t.Skip("YARA-X binary not found - run in container for full test")
	}

	// Create multipart form with empty filename
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", "")
	if err != nil {
		t.Fatal(err)
	}
	part.Write([]byte("test content"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/scan", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()

	handleScan(w, req)

	// Should still work (empty filename is valid)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// Integration test: full scan flow with a matching file
func TestIntegrationScanWithMatch(t *testing.T) {
	// Skip if test rules directory doesn't exist
	if _, err := os.Stat("./test"); os.IsNotExist(err) {
		t.Skip("test rules directory not found")
	}

	// Skip if YARA-X binary not available (integration test)
	if _, err := os.Stat("/usr/local/bin/yr"); os.IsNotExist(err) {
		t.Skip("YARA-X binary not found - run in container for full test")
	}

	// Create multipart form with content that should match a test rule
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatal(err)
	}
	// Write content that matches Test_Rule in test.yar (if it exists)
	part.Write([]byte("YARA_TEST_STRING_12345"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/scan", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()

	handleScan(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp ScanResponse
	json.NewDecoder(w.Body).Decode(&resp)

	// Verify we got a valid response structure
	if resp.ScannedFiles != 1 {
		t.Errorf("scanned_files = %d, want 1", resp.ScannedFiles)
	}

	// Note: match count depends on rules in ./test directory
	t.Logf("Scan result: %d matches, %d files, %dms",
		len(resp.Matches), resp.ScannedFiles, resp.ScanTimeMs)
}
