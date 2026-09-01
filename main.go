package main

import (
	"fmt"
	"io"
	"os"
)

const maxInputSize = 512 << 20

func main() {
	if err := run(os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "gvm2excel: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stderr io.Writer) error {
	if len(args) < 1 || len(args) > 2 {
		return fmt.Errorf("usage: gvm2excel input.xml [output.xlsx]")
	}

	inputPath := args[0]
	outputPath := "report.xlsx"
	if len(args) == 2 {
		outputPath = args[1]
	}
	if inputPath == outputPath {
		return fmt.Errorf("input and output paths must differ")
	}

	input, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer func() {
		if closeErr := input.Close(); closeErr != nil {
			fmt.Fprintf(stderr, "gvm2excel: close input: %v\n", closeErr)
		}
	}()
	info, err := input.Stat()
	if err != nil {
		return fmt.Errorf("inspect input: %w", err)
	}
	if info.Size() > maxInputSize {
		return fmt.Errorf("input exceeds %d MiB limit", maxInputSize>>20)
	}

	parsed, err := parseReport(input)
	if err != nil {
		return err
	}
	return writeWorkbook(outputPath, parsed)
}
