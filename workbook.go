package main

import (
	"fmt"
	"sort"

	"github.com/xuri/excelize/v2"
)

const generalSheet = "Geral"

var severitySheets = []struct {
	name   string
	labels map[string]bool
	color  string
}{
	{"Crítico", map[string]bool{"Crítica": true, "Alta": true, "High": true}, "C00000"},
	{"Médio", map[string]bool{"Média": true, "Medium": true}, "ED7D31"},
	{"Baixo", map[string]bool{"Baixa": true, "Low": true}, "4472C4"},
	{"Alarm", map[string]bool{"Alarm": true}, "7030A0"},
	{"Log", map[string]bool{"Log": true, "Informativa": true}, "70AD47"},
	{"Debug", map[string]bool{"Debug": true}, "5B9BD5"},
}

func writeWorkbook(path string, data report) error {
	book := excelize.NewFile()
	defer func() { _ = book.Close() }()
	if err := book.SetSheetName("Sheet1", generalSheet); err != nil {
		return fmt.Errorf("rename general sheet: %w", err)
	}
	if err := buildGeneralSheet(book, data); err != nil {
		return err
	}
	for _, definition := range severitySheets {
		items := filterFindings(data.Findings, definition.labels)
		if err := buildFindingsSheet(book, definition.name, items, definition.color); err != nil {
			return err
		}
	}
	if err := buildErrorsSheet(book, data.Errors); err != nil {
		return err
	}
	if err := buildHostsRankingSheet(book, data.Findings); err != nil {
		return err
	}
	if err := buildReportHostsSheet(book, data.Hosts); err != nil {
		return err
	}
	book.SetActiveSheet(0)
	if err := book.SaveAs(path); err != nil {
		return fmt.Errorf("save workbook: %w", err)
	}
	return nil
}

func buildGeneralSheet(book *excelize.File, data report) error {
	counts := make(map[string]int)
	for _, item := range data.Findings {
		counts[summaryLabel(item.Threat)]++
	}
	if err := setRow(book, generalSheet, "A1", []any{"Resumo", "Quantidade"}); err != nil {
		return err
	}
	if err := setRow(book, generalSheet, "A2", []any{"Vulnerabilidades", len(data.Findings)}); err != nil {
		return err
	}
	if err := setRow(book, generalSheet, "A3", []any{"Possíveis falhas", len(data.Errors)}); err != nil {
		return err
	}
	if err := setRow(book, generalSheet, "D1", []any{"Severidade", "Quantidade"}); err != nil {
		return err
	}
	labels := []string{"Crítica", "Alta", "Média", "Baixa", "Informativa"}
	colors := []string{"8B0000", "C00000", "ED7D31", "4472C4", "70AD47"}
	for index, label := range labels {
		if err := setRow(book, generalSheet, fmt.Sprintf("D%d", index+2), []any{label, counts[label]}); err != nil {
			return err
		}
	}
	if err := setWidths(book, generalSheet, map[string]float64{"A": 24, "B": 14, "D": 18, "E": 14}); err != nil {
		return err
	}
	if err := styleRanges(book, generalSheet, []string{"A1:B1", "D1:E1"}, "1F4E78", "A2:E7"); err != nil {
		return err
	}
	points := make([]excelize.ChartDataPoint, len(colors))
	for index, color := range colors {
		points[index] = excelize.ChartDataPoint{
			Index: index,
			Fill:  excelize.Fill{Type: "pattern", Color: []string{color}, Pattern: 1},
		}
	}
	return book.AddChart(generalSheet, "G2", &excelize.Chart{
		Type: excelize.Pie3D,
		Series: []excelize.ChartSeries{{
			Name: generalSheet + "!$E$1", Categories: generalSheet + "!$D$2:$D$6",
			Values: generalSheet + "!$E$2:$E$6", DataPoint: points,
		}},
		Title:    excelize.ChartTitle{Paragraph: []excelize.RichTextRun{{Text: "Mapa de risco"}}},
		Legend:   excelize.ChartLegend{Position: "right"},
		PlotArea: excelize.ChartPlotArea{ShowPercent: true, ShowCatName: true, ShowVal: true},
		Format:   excelize.GraphicOptions{ScaleX: 1.35, ScaleY: 1.25},
	})
}

func buildFindingsSheet(book *excelize.File, sheet string, findings []finding, color string) error {
	if _, err := book.NewSheet(sheet); err != nil {
		return fmt.Errorf("create %s sheet: %w", sheet, err)
	}
	if err := setRow(book, sheet, "A1", []any{
		"Ameaça", "Nome", "Host", "Porta", "CVSS", "Família", "Descrição", "Solução", "Referências",
	}); err != nil {
		return err
	}
	for index, item := range findings {
		if err := setRow(book, sheet, fmt.Sprintf("A%d", index+2), []any{
			item.Threat, item.Name, item.Host, item.Port, item.Severity, item.Family,
			item.Description, item.Solution, item.References,
		}); err != nil {
			return err
		}
	}
	if err := formatFindingsSheet(book, sheet, len(findings)+1, color); err != nil {
		return err
	}
	return nil
}

func buildErrorsSheet(book *excelize.File, errors []scanError) error {
	const sheet = "Possíveis falhas"
	if _, err := book.NewSheet(sheet); err != nil {
		return err
	}
	if err := setRow(book, sheet, "A1", []any{"Host", "Porta", "Falha", "CVSS"}); err != nil {
		return err
	}
	for index, item := range errors {
		if err := setRow(book, sheet, fmt.Sprintf("A%d", index+2), []any{item.Host, item.Port, item.Name, item.Severity}); err != nil {
			return err
		}
	}
	if err := setWidths(book, sheet, map[string]float64{"A": 22, "B": 18, "C": 55, "D": 12}); err != nil {
		return err
	}
	return formatTable(book, sheet, len(errors)+1, 4, "C00000")
}

func buildHostsRankingSheet(book *excelize.File, findings []finding) error {
	const sheet = "Vulns por Host"
	if _, err := book.NewSheet(sheet); err != nil {
		return err
	}
	counts := make(map[string]int)
	for _, item := range findings {
		counts[item.Host]++
	}
	type hostCount struct {
		host  string
		count int
	}
	hosts := make([]hostCount, 0, len(counts))
	for host, count := range counts {
		hosts = append(hosts, hostCount{host, count})
	}
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].count != hosts[j].count {
			return hosts[i].count > hosts[j].count
		}
		return hosts[i].host < hosts[j].host
	})
	if err := setRow(book, sheet, "A1", []any{"Host", "Vulnerabilidades"}); err != nil {
		return err
	}
	for index, item := range hosts {
		if err := setRow(book, sheet, fmt.Sprintf("A%d", index+2), []any{item.host, item.count}); err != nil {
			return err
		}
	}
	if err := setWidths(book, sheet, map[string]float64{"A": 34, "B": 18}); err != nil {
		return err
	}
	if err := formatTable(book, sheet, len(hosts)+1, 2, "C00000"); err != nil {
		return err
	}
	if len(hosts) == 0 {
		return nil
	}
	limit := len(hosts)
	if limit > 10 {
		limit = 10
	}
	return book.AddChart(sheet, "D2", &excelize.Chart{
		Type: excelize.Bar3DClustered,
		Series: []excelize.ChartSeries{{
			Name: sheet + "!$B$1", Categories: fmt.Sprintf("'%s'!$A$2:$A$%d", sheet, limit+1),
			Values: fmt.Sprintf("'%s'!$B$2:$B$%d", sheet, limit+1),
			Fill:   excelize.Fill{Type: "pattern", Color: []string{"C00000"}, Pattern: 1},
		}},
		Title:  excelize.ChartTitle{Paragraph: []excelize.RichTextRun{{Text: "Top 10 hosts"}}},
		Legend: excelize.ChartLegend{Position: "none"}, PlotArea: excelize.ChartPlotArea{ShowVal: true},
		Format: excelize.GraphicOptions{ScaleX: 1.4, ScaleY: 1.35},
	})
}

func buildReportHostsSheet(book *excelize.File, hosts []reportHost) error {
	const sheet = "Hosts"
	if _, err := book.NewSheet(sheet); err != nil {
		return err
	}
	if err := setRow(book, sheet, "A1", []any{"Host", "Tipo", "Valor", "Criticidade", "Detalhes"}); err != nil {
		return err
	}
	row := 2
	for _, host := range hosts {
		if len(host.Details) == 0 {
			if err := setRow(book, sheet, fmt.Sprintf("A%d", row), []any{host.IP}); err != nil {
				return err
			}
			row++
			continue
		}
		for _, detail := range host.Details {
			if err := setRow(book, sheet, fmt.Sprintf("A%d", row), []any{
				host.IP, detail.Name, detail.Value, detail.Extra, detail.Description,
			}); err != nil {
				return err
			}
			row++
		}
	}
	if err := setWidths(book, sheet, map[string]float64{"A": 22, "B": 34, "C": 34, "D": 18, "E": 55}); err != nil {
		return err
	}
	return formatTable(book, sheet, row-1, 5, "7030A0")
}

func filterFindings(findings []finding, labels map[string]bool) []finding {
	filtered := make([]finding, 0)
	for _, item := range findings {
		if labels[item.Threat] {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func summaryLabel(label string) string {
	switch label {
	case "Crítica", "Alta", "Média", "Baixa":
		return label
	default:
		return "Informativa"
	}
}

func formatFindingsSheet(book *excelize.File, sheet string, rows int, color string) error {
	if err := setWidths(book, sheet, map[string]float64{
		"A": 14, "B": 38, "C": 24, "D": 18, "E": 10, "F": 24, "G": 60, "H": 60, "I": 45,
	}); err != nil {
		return err
	}
	return formatTable(book, sheet, rows, 9, color)
}

func formatTable(book *excelize.File, sheet string, rows, columns int, color string) error {
	lastColumn, err := excelize.ColumnNumberToName(columns)
	if err != nil {
		return err
	}
	if err := styleRanges(book, sheet, []string{"A1:" + lastColumn + "1"}, color,
		fmt.Sprintf("A2:%s%d", lastColumn, max(rows, 2))); err != nil {
		return err
	}
	if err := book.AutoFilter(sheet, fmt.Sprintf("A1:%s%d", lastColumn, max(rows, 1)), nil); err != nil {
		return fmt.Errorf("enable %s filter: %w", sheet, err)
	}
	return book.SetPanes(sheet, &excelize.Panes{Freeze: true, YSplit: 1, TopLeftCell: "A2"})
}

func styleRanges(book *excelize.File, sheet string, headers []string, color, bodyRange string) error {
	headerStyle, err := book.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Color: "FFFFFF"}, Fill: excelize.Fill{Type: "pattern", Color: []string{color}, Pattern: 1},
		Alignment: &excelize.Alignment{Vertical: "center", Horizontal: "center", WrapText: true},
	})
	if err != nil {
		return err
	}
	bodyStyle, err := book.NewStyle(&excelize.Style{Alignment: &excelize.Alignment{Vertical: "top", WrapText: true}})
	if err != nil {
		return err
	}
	for _, header := range headers {
		if err := book.SetCellStyle(sheet, header[:2], header[3:], headerStyle); err != nil {
			return err
		}
	}
	parts := splitRange(bodyRange)
	return book.SetCellStyle(sheet, parts[0], parts[1], bodyStyle)
}

func splitRange(value string) [2]string {
	for index, char := range value {
		if char == ':' {
			return [2]string{value[:index], value[index+1:]}
		}
	}
	return [2]string{value, value}
}

func setWidths(book *excelize.File, sheet string, widths map[string]float64) error {
	for column, width := range widths {
		if err := book.SetColWidth(sheet, column, column, width); err != nil {
			return fmt.Errorf("set %s width: %w", sheet, err)
		}
	}
	return nil
}

func setRow(book *excelize.File, sheet, cell string, row []any) error {
	if err := book.SetSheetRow(sheet, cell, &row); err != nil {
		return fmt.Errorf("write %s row: %w", sheet, err)
	}
	return nil
}
