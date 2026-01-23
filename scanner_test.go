package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testConfig returns a Config with sensible test defaults
func testConfig() *Config {
	return &Config{
		Port:              "9001",
		DebugMode:         false,
		RulesPath:         "./test",
		MaxUploadSize:     10 << 20, // 10MB
		MaxExtractedSize:  50 << 20, // 50MB
		MaxFileCount:      100,
		MaxSingleFileSize: 5 << 20, // 5MB
		ScanTimeout:       1 * time.Minute,
	}
}

func TestParseYaraXOutput(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantMatches int
		wantRule    string
		wantErr     bool
	}{
		{
			name:        "empty output",
			input:       "",
			wantMatches: 0,
			wantErr:     false,
		},
		{
			name:        "single match",
			input:       `{"path":"/tmp/test.txt","rules":[{"identifier":"Test_Rule","namespace":"default"}]}`,
			wantMatches: 1,
			wantRule:    "Test_Rule",
			wantErr:     false,
		},
		{
			name:        "match with metadata",
			input:       `{"path":"/tmp/test.txt","rules":[{"identifier":"Malware_Test","namespace":"default","meta":[["severity","HIGH"],["description","Test malware"]]}]}`,
			wantMatches: 1,
			wantRule:    "Malware_Test",
			wantErr:     false,
		},
		{
			name:        "multiple matches in one file",
			input:       `{"path":"/tmp/test.txt","rules":[{"identifier":"Rule1","namespace":"default"},{"identifier":"Rule2","namespace":"default"}]}`,
			wantMatches: 2,
			wantErr:     false,
		},
		{
			name: "multiple files (NDJSON)",
			input: `{"path":"/tmp/file1.txt","rules":[{"identifier":"Rule1"}]}
{"path":"/tmp/file2.txt","rules":[{"identifier":"Rule2"}]}`,
			wantMatches: 2,
			wantErr:     false,
		},
		{
			name:        "invalid JSON line is skipped",
			input:       "not valid json\n" + `{"path":"/tmp/test.txt","rules":[{"identifier":"Test"}]}`,
			wantMatches: 1,
			wantRule:    "Test",
			wantErr:     false,
		},
		{
			name:        "no matches (empty rules array)",
			input:       `{"path":"/tmp/clean.txt","rules":[]}`,
			wantMatches: 0,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := parseYaraXOutput([]byte(tt.input))

			if (err != nil) != tt.wantErr {
				t.Errorf("parseYaraXOutput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(matches) != tt.wantMatches {
				t.Errorf("parseYaraXOutput() got %d matches, want %d", len(matches), tt.wantMatches)
			}

			if tt.wantRule != "" && len(matches) > 0 {
				if matches[0].Rule != tt.wantRule {
					t.Errorf("parseYaraXOutput() rule = %q, want %q", matches[0].Rule, tt.wantRule)
				}
			}
		})
	}
}

func TestParseYaraXOutputMetadata(t *testing.T) {
	// YARA-X outputs meta as array of [key, value] pairs
	input := `{"path":"/tmp/test.txt","rules":[{"identifier":"Test_Rule","tags":["malware","trojan"],"meta":[["severity","CRITICAL"],["description","Test description"]]}]}`

	matches, err := parseYaraXOutput([]byte(input))
	if err != nil {
		t.Fatalf("parseYaraXOutput() error = %v", err)
	}

	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	match := matches[0]

	if match.Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want %q", match.Severity, "CRITICAL")
	}

	if match.Description != "Test description" {
		t.Errorf("Description = %q, want %q", match.Description, "Test description")
	}

	if len(match.Tags) != 2 {
		t.Errorf("Tags count = %d, want 2", len(match.Tags))
	}
}

func TestIsNotZipError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "not a valid zip file error",
			err:      zip.ErrFormat,
			expected: true,
		},
		{
			name:     "unexpected EOF",
			err:      &testError{"unexpected EOF"},
			expected: true,
		},
		{
			name:     "other error",
			err:      &testError{"some other error"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNotZipError(tt.err)
			if result != tt.expected {
				t.Errorf("isNotZipError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

// testError is a simple error type for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestExtractZipSafe(t *testing.T) {
	cfg := testConfig()
	scanner := NewScanner(cfg)

	t.Run("extracts valid zip", func(t *testing.T) {
		// Create a temp zip file
		zipPath := createTestZip(t, map[string]string{
			"file1.txt": "content1",
			"file2.txt": "content2",
		})
		defer os.Remove(zipPath)

		// Create temp extraction directory
		extractDir, err := os.MkdirTemp("", "extract-test-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(extractDir)

		count, err := scanner.extractZipSafe(zipPath, extractDir)
		if err != nil {
			t.Errorf("extractZipSafe() error = %v", err)
		}

		if count != 2 {
			t.Errorf("extractZipSafe() count = %d, want 2", count)
		}

		// Verify files exist
		if _, err := os.Stat(filepath.Join(extractDir, "file1.txt")); os.IsNotExist(err) {
			t.Error("file1.txt not extracted")
		}
	})

	t.Run("rejects too many files", func(t *testing.T) {
		// Create config with low file limit
		limitedCfg := testConfig()
		limitedCfg.MaxFileCount = 2
		limitedScanner := NewScanner(limitedCfg)

		zipPath := createTestZip(t, map[string]string{
			"file1.txt": "a",
			"file2.txt": "b",
			"file3.txt": "c",
		})
		defer os.Remove(zipPath)

		extractDir, _ := os.MkdirTemp("", "extract-test-")
		defer os.RemoveAll(extractDir)

		_, err := limitedScanner.extractZipSafe(zipPath, extractDir)
		if err == nil {
			t.Error("expected error for too many files")
		}
		if !strings.Contains(err.Error(), "too many files") {
			t.Errorf("expected 'too many files' error, got: %v", err)
		}
	})

	t.Run("prevents zip slip attack", func(t *testing.T) {
		// Create a zip with path traversal attempt
		zipPath := createZipSlipAttempt(t)
		defer os.Remove(zipPath)

		extractDir, _ := os.MkdirTemp("", "extract-test-")
		defer os.RemoveAll(extractDir)

		// Should not error, but should skip the malicious file
		_, err := scanner.extractZipSafe(zipPath, extractDir)
		if err != nil {
			t.Errorf("extractZipSafe() error = %v", err)
		}

		// Verify no file escaped to parent directory
		parentFile := filepath.Join(extractDir, "..", "escaped.txt")
		if _, err := os.Stat(parentFile); !os.IsNotExist(err) {
			t.Error("zip slip attack succeeded - file escaped target directory")
		}
	})
}

func TestCopySingleFile(t *testing.T) {
	cfg := testConfig()
	scanner := NewScanner(cfg)

	t.Run("copies file successfully", func(t *testing.T) {
		// Create source file
		srcFile, err := os.CreateTemp("", "src-*.txt")
		if err != nil {
			t.Fatal(err)
		}
		srcFile.WriteString("test content")
		srcFile.Close()
		defer os.Remove(srcFile.Name())

		// Create target directory
		targetDir, _ := os.MkdirTemp("", "target-")
		defer os.RemoveAll(targetDir)

		count, err := scanner.copySingleFile(srcFile.Name(), targetDir)
		if err != nil {
			t.Errorf("copySingleFile() error = %v", err)
		}
		if count != 1 {
			t.Errorf("copySingleFile() count = %d, want 1", count)
		}
	})

	t.Run("rejects file exceeding size limit", func(t *testing.T) {
		// Create config with small limit
		limitedCfg := testConfig()
		limitedCfg.MaxSingleFileSize = 10 // 10 bytes
		limitedScanner := NewScanner(limitedCfg)

		// Create source file larger than limit
		srcFile, _ := os.CreateTemp("", "large-*.txt")
		srcFile.WriteString("this content is longer than 10 bytes")
		srcFile.Close()
		defer os.Remove(srcFile.Name())

		targetDir, _ := os.MkdirTemp("", "target-")
		defer os.RemoveAll(targetDir)

		_, err := limitedScanner.copySingleFile(srcFile.Name(), targetDir)
		if err == nil {
			t.Error("expected error for oversized file")
		}
		if !strings.Contains(err.Error(), "exceeds size limit") {
			t.Errorf("expected 'exceeds size limit' error, got: %v", err)
		}
	})
}

func TestComputeFileHash(t *testing.T) {
	// Create a temp file with known content
	tmpFile, err := os.CreateTemp("", "hash-test-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// Write known content
	tmpFile.WriteString("hello world")
	tmpFile.Close()

	hash, err := computeFileHash(tmpFile.Name())
	if err != nil {
		t.Errorf("computeFileHash() error = %v", err)
	}

	// SHA256 of "hello world"
	expected := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if hash != expected {
		t.Errorf("computeFileHash() = %q, want %q", hash, expected)
	}
}

func TestFindRuleFiles(t *testing.T) {
	// Create temp directory with rule files
	rulesDir, err := os.MkdirTemp("", "rules-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(rulesDir)

	// Create test rule files
	os.WriteFile(filepath.Join(rulesDir, "rule1.yar"), []byte("rule test1 { condition: true }"), 0644)
	os.WriteFile(filepath.Join(rulesDir, "rule2.yara"), []byte("rule test2 { condition: true }"), 0644)
	os.WriteFile(filepath.Join(rulesDir, "notarule.txt"), []byte("not a rule"), 0644)

	// Create subdirectory with more rules
	subDir := filepath.Join(rulesDir, "sub")
	os.Mkdir(subDir, 0755)
	os.WriteFile(filepath.Join(subDir, "rule3.yar"), []byte("rule test3 { condition: true }"), 0644)

	cfg := testConfig()
	cfg.RulesPath = rulesDir
	scanner := NewScanner(cfg)

	files, err := scanner.findRuleFiles()
	if err != nil {
		t.Errorf("findRuleFiles() error = %v", err)
	}

	// Should find 3 rule files (.yar and .yara), not the .txt
	if len(files) != 3 {
		t.Errorf("findRuleFiles() found %d files, want 3", len(files))
	}
}

// Helper: creates a test zip file with given files
func createTestZip(t *testing.T, files map[string]string) string {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "test-*.zip")
	if err != nil {
		t.Fatal(err)
	}

	w := zip.NewWriter(tmpFile)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte(content))
	}
	w.Close()
	tmpFile.Close()

	return tmpFile.Name()
}

// Helper: creates a zip with path traversal attempt
func createZipSlipAttempt(t *testing.T) string {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "zipslip-*.zip")
	if err != nil {
		t.Fatal(err)
	}

	w := zip.NewWriter(tmpFile)

	// Create a file with path traversal in name
	f, err := w.Create("../escaped.txt")
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("escaped content"))

	// Also add a normal file
	f2, _ := w.Create("normal.txt")
	f2.Write([]byte("normal content"))

	w.Close()
	tmpFile.Close()

	return tmpFile.Name()
}

func TestComputeFileHashError(t *testing.T) {
	// Test with non-existent file
	_, err := computeFileHash("/nonexistent/file.txt")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestFindRuleFilesError(t *testing.T) {
	cfg := testConfig()
	cfg.RulesPath = "/nonexistent/rules/path"
	scanner := NewScanner(cfg)

	_, err := scanner.findRuleFiles()
	if err == nil {
		t.Error("expected error for non-existent rules path")
	}
}

func TestExtractZipSafeFileSizeLimit(t *testing.T) {
	cfg := testConfig()
	cfg.MaxSingleFileSize = 5 // 5 bytes limit
	scanner := NewScanner(cfg)

	// Create zip with file larger than limit
	zipPath := createTestZip(t, map[string]string{
		"large.txt": "this content is larger than 5 bytes",
	})
	defer os.Remove(zipPath)

	extractDir, _ := os.MkdirTemp("", "extract-test-")
	defer os.RemoveAll(extractDir)

	_, err := scanner.extractZipSafe(zipPath, extractDir)
	if err == nil {
		t.Error("expected error for file exceeding size limit")
	}
	if !strings.Contains(err.Error(), "exceeds size limit") {
		t.Errorf("expected 'exceeds size limit' error, got: %v", err)
	}
}

func TestExtractZipSafeTotalSizeLimit(t *testing.T) {
	cfg := testConfig()
	cfg.MaxExtractedSize = 10 // 10 bytes total limit
	scanner := NewScanner(cfg)

	// Create zip with total content larger than limit
	zipPath := createTestZip(t, map[string]string{
		"file1.txt": "12345",
		"file2.txt": "67890",
		"file3.txt": "abcde", // This pushes total over 10 bytes
	})
	defer os.Remove(zipPath)

	extractDir, _ := os.MkdirTemp("", "extract-test-")
	defer os.RemoveAll(extractDir)

	_, err := scanner.extractZipSafe(zipPath, extractDir)
	if err == nil {
		t.Error("expected error for total size exceeding limit")
	}
	if !strings.Contains(err.Error(), "exceeds total size limit") {
		t.Errorf("expected 'exceeds total size limit' error, got: %v", err)
	}
}

func TestExtractZipSafeWithDirectories(t *testing.T) {
	cfg := testConfig()
	scanner := NewScanner(cfg)

	// Create zip with nested directory structure
	tmpFile, err := os.CreateTemp("", "nested-*.zip")
	if err != nil {
		t.Fatal(err)
	}

	w := zip.NewWriter(tmpFile)

	// Add directory entry
	w.Create("subdir/")

	// Add file in subdirectory
	f, _ := w.Create("subdir/nested.txt")
	f.Write([]byte("nested content"))

	w.Close()
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	extractDir, _ := os.MkdirTemp("", "extract-test-")
	defer os.RemoveAll(extractDir)

	count, err := scanner.extractZipSafe(tmpFile.Name(), extractDir)
	if err != nil {
		t.Errorf("extractZipSafe() error = %v", err)
	}

	// Should count the directory and the file
	if count < 1 {
		t.Errorf("extractZipSafe() count = %d, want >= 1", count)
	}

	// Verify nested file exists
	nestedPath := filepath.Join(extractDir, "subdir", "nested.txt")
	if _, err := os.Stat(nestedPath); os.IsNotExist(err) {
		t.Error("nested file not extracted")
	}
}

func TestCopySingleFileSourceError(t *testing.T) {
	cfg := testConfig()
	scanner := NewScanner(cfg)

	targetDir, _ := os.MkdirTemp("", "target-")
	defer os.RemoveAll(targetDir)

	// Try to copy non-existent file
	_, err := scanner.copySingleFile("/nonexistent/file.txt", targetDir)
	if err == nil {
		t.Error("expected error for non-existent source file")
	}
}

func TestParseYaraXOutputWithStrings(t *testing.T) {
	// Test parsing output that includes matched strings (compact JSON)
	// Note: patterns field uses the original struct format
	input := `{"path":"/tmp/test.txt","rules":[{"identifier":"Test_Rule","meta":[],"patterns":[{"identifier":"$test","matches":[{"offset":0,"length":4,"data":"test"}]}]}]}`

	matches, err := parseYaraXOutput([]byte(input))
	if err != nil {
		t.Fatalf("parseYaraXOutput() error = %v", err)
	}

	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	if len(matches[0].Strings) != 1 {
		t.Errorf("expected 1 matched string, got %d", len(matches[0].Strings))
	}

	if matches[0].Strings[0] != "test" {
		t.Errorf("matched string = %q, want %q", matches[0].Strings[0], "test")
	}
}

func TestNewScanner(t *testing.T) {
	cfg := testConfig()
	scanner := NewScanner(cfg)

	if scanner == nil {
		t.Fatal("NewScanner returned nil")
	}

	if scanner.config != cfg {
		t.Error("scanner config not set correctly")
	}
}

func TestExtractFileSafeError(t *testing.T) {
	cfg := testConfig()
	scanner := NewScanner(cfg)

	// Create a valid zip file
	zipPath := createTestZip(t, map[string]string{
		"test.txt": "content",
	})
	defer os.Remove(zipPath)

	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	// Try to extract to an invalid path
	invalidPath := "/nonexistent/dir/file.txt"
	err = scanner.extractFileSafe(reader.File[0], invalidPath)
	if err == nil {
		t.Error("expected error when extracting to invalid path")
	}
}

func TestCopySingleFileDestinationError(t *testing.T) {
	cfg := testConfig()
	scanner := NewScanner(cfg)

	// Create source file
	srcFile, err := os.CreateTemp("", "src-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	srcFile.WriteString("test content")
	srcFile.Close()
	defer os.Remove(srcFile.Name())

	// Try to copy to non-existent directory
	_, err = scanner.copySingleFile(srcFile.Name(), "/nonexistent/target/dir")
	if err == nil {
		t.Error("expected error when copying to non-existent directory")
	}
}

func TestExtractZipSafeInvalidZip(t *testing.T) {
	cfg := testConfig()
	scanner := NewScanner(cfg)

	// Create a file that isn't a valid zip
	tmpFile, err := os.CreateTemp("", "notzip-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.WriteString("this is not a zip file")
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	extractDir, _ := os.MkdirTemp("", "extract-test-")
	defer os.RemoveAll(extractDir)

	_, err = scanner.extractZipSafe(tmpFile.Name(), extractDir)
	if err == nil {
		t.Error("expected error for invalid zip file")
	}
}

func TestIsNotZipErrorVariations(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected bool
	}{
		{"zip format error message", "zip: not a valid zip file", true},
		{"EOF error", "unexpected EOF", true},
		{"permission denied", "permission denied", false},
		{"file not found", "no such file", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &testError{tt.errMsg}
			result := isNotZipError(err)
			if result != tt.expected {
				t.Errorf("isNotZipError(%q) = %v, want %v", tt.errMsg, result, tt.expected)
			}
		})
	}
}
