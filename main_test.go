package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "input.xml")
	output := filepath.Join(directory, "output.xlsx")
	if err := os.WriteFile(input, []byte(syntheticReport), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{input, output}, io.Discard); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if _, err := os.Stat(output); err != nil {
		t.Fatalf("output not created: %v", err)
	}
}

func TestRunRejectsInvalidArguments(t *testing.T) {
	tests := [][]string{nil, {"a", "b", "c"}, {"same", "same"}}
	for _, args := range tests {
		if err := run(args, io.Discard); err == nil {
			t.Errorf("run(%v) error = nil, want error", args)
		}
	}
}

func TestRunRejectsMalformedXML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.xml")
	if err := os.WriteFile(path, []byte(`<report>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{path}, io.Discard); err == nil || !strings.Contains(err.Error(), "parse XML") {
		t.Fatalf("run() error = %v", err)
	}
}
