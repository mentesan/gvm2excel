package main

import (
	"archive/zip"
	"bytes"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/xuri/excelize/v2"
)

func TestWriteWorkbook(t *testing.T) {
	parsed, err := parseReport(strings.NewReader(syntheticReport))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "report.xlsx")
	if err := writeWorkbook(path, parsed); err != nil {
		t.Fatalf("writeWorkbook() error = %v", err)
	}

	book, err := excelize.OpenFile(path)
	if err != nil {
		t.Fatalf("open generated workbook: %v", err)
	}
	defer func() { _ = book.Close() }()
	wantSheets := []string{"Geral", "Crítico", "Médio", "Baixo", "Alarm", "Log", "Debug", "Possíveis falhas", "Vulns por Host", "Hosts"}
	if got := book.GetSheetList(); !slices.Equal(got, wantSheets) {
		t.Fatalf("sheets = %v", got)
	}
	if got, err := book.GetCellValue("Crítico", "B2"); err != nil || got != "Critical example" {
		t.Errorf("Crítico!B2 = %q, %v", got, err)
	}
	archive, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("open workbook archive: %v", err)
	}
	defer archive.Close()
	chartCount := 0
	var pieChart []byte
	for _, file := range archive.File {
		if strings.HasPrefix(file.Name, "xl/charts/chart") && strings.HasSuffix(file.Name, ".xml") {
			chartCount++
			reader, err := file.Open()
			if err != nil {
				t.Fatal(err)
			}
			content, err := io.ReadAll(reader)
			_ = reader.Close()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(content, []byte("<pie3DChart>")) {
				pieChart = content
			}
		}
	}
	if chartCount != 2 {
		t.Errorf("chart count = %d, want 2", chartCount)
	}
	for _, color := range []string{"8B0000", "C00000", "ED7D31", "4472C4", "70AD47"} {
		if !bytes.Contains(pieChart, []byte(`srgbClr val="`+color+`"`)) {
			t.Errorf("3D pie chart does not contain color %s", color)
		}
	}
}
