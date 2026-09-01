package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

type report struct {
	Findings []finding
	Errors   []scanError
	Hosts    []reportHost
}

type finding struct {
	Name        string
	Host        string
	Port        string
	Severity    float64
	Threat      string
	Family      string
	Description string
	Solution    string
	References  string
}

type xmlResult struct {
	Name        string  `xml:"name"`
	Host        xmlHost `xml:"host"`
	Port        string  `xml:"port"`
	Threat      string  `xml:"threat"`
	Severity    string  `xml:"severity"`
	Description string  `xml:"description"`
	NVT         xmlNVT  `xml:"nvt"`
}

type xmlHost struct {
	Address  string `xml:",chardata"`
	Hostname string `xml:"hostname"`
}

type xmlNVT struct {
	Name       string         `xml:"name"`
	Family     string         `xml:"family"`
	CVSS       string         `xml:"cvss_base"`
	Tags       string         `xml:"tags"`
	Solution   string         `xml:"solution"`
	References []xmlReference `xml:"refs>ref"`
}

type xmlReference struct {
	Type string `xml:"type,attr"`
	ID   string `xml:"id,attr"`
}

type scanError struct {
	Host     string
	Port     string
	Name     string
	Severity float64
}

type reportHost struct {
	IP      string
	Details []hostDetail
}

type hostDetail struct {
	Name        string
	Value       string
	Extra       string
	SourceType  string
	Description string
}

type xmlError struct {
	Host string `xml:"host"`
	Port string `xml:"port"`
	NVT  xmlNVT `xml:"nvt"`
}

type xmlReportHost struct {
	IP      string      `xml:"ip"`
	Details []xmlDetail `xml:"detail"`
}

type xmlDetail struct {
	Name   string    `xml:"name"`
	Value  string    `xml:"value"`
	Extra  string    `xml:"extra"`
	Source xmlSource `xml:"source"`
}

type xmlSource struct {
	Type        string `xml:"type"`
	Description string `xml:"description"`
}

func parseReport(r io.Reader) (report, error) {
	decoder := xml.NewDecoder(r)
	var parsed report
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return report{}, fmt.Errorf("parse XML: %w", err)
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "result":
			var source xmlResult
			if err := decoder.DecodeElement(&source, &start); err != nil {
				return report{}, fmt.Errorf("parse result: %w", err)
			}
			if strings.TrimSpace(source.Name) != "" && strings.TrimSpace(source.Host.Address) != "" {
				parsed.Findings = append(parsed.Findings, normalizeFinding(source))
			}
		case "error":
			var source xmlError
			if err := decoder.DecodeElement(&source, &start); err != nil {
				return report{}, fmt.Errorf("parse scan error: %w", err)
			}
			if strings.TrimSpace(source.Host) != "" {
				severity, _ := strconv.ParseFloat(strings.TrimSpace(source.NVT.CVSS), 64)
				parsed.Errors = append(parsed.Errors, scanError{
					Host: strings.TrimSpace(source.Host), Port: strings.TrimSpace(source.Port),
					Name: strings.TrimSpace(source.NVT.Name), Severity: severity,
				})
			}
		case "host":
			var source xmlReportHost
			if err := decoder.DecodeElement(&source, &start); err != nil {
				return report{}, fmt.Errorf("parse host: %w", err)
			}
			if strings.TrimSpace(source.IP) != "" {
				parsed.Hosts = append(parsed.Hosts, normalizeHost(source))
			}
		}
	}
	if len(parsed.Findings) == 0 {
		return report{}, fmt.Errorf("XML does not contain GVM findings")
	}

	sort.SliceStable(parsed.Findings, func(i, j int) bool {
		if parsed.Findings[i].Severity != parsed.Findings[j].Severity {
			return parsed.Findings[i].Severity > parsed.Findings[j].Severity
		}
		if parsed.Findings[i].Host != parsed.Findings[j].Host {
			return parsed.Findings[i].Host < parsed.Findings[j].Host
		}
		return parsed.Findings[i].Name < parsed.Findings[j].Name
	})
	sort.SliceStable(parsed.Errors, func(i, j int) bool { return parsed.Errors[i].Severity > parsed.Errors[j].Severity })
	return parsed, nil
}

func normalizeHost(source xmlReportHost) reportHost {
	host := reportHost{IP: strings.TrimSpace(source.IP)}
	for _, detail := range source.Details {
		name := strings.TrimSpace(detail.Name)
		if name == "EXIT_CODE" || strings.HasPrefix(name, "scanned_with_") {
			continue
		}
		host.Details = append(host.Details, hostDetail{
			Name: name, Value: strings.TrimSpace(detail.Value), Extra: strings.TrimSpace(detail.Extra),
			SourceType:  strings.TrimSpace(detail.Source.Type),
			Description: strings.TrimSpace(detail.Source.Description),
		})
	}
	return host
}

func normalizeFinding(source xmlResult) finding {
	severity, _ := strconv.ParseFloat(strings.TrimSpace(source.Severity), 64)
	if severity == 0 {
		severity, _ = strconv.ParseFloat(strings.TrimSpace(source.NVT.CVSS), 64)
	}
	host := strings.TrimSpace(source.Host.Address)
	if hostname := strings.TrimSpace(source.Host.Hostname); hostname != "" {
		host += " (" + hostname + ")"
	}
	description := strings.TrimSpace(source.Description)
	if description == "" {
		description = descriptionFromTags(source.NVT.Tags)
	}
	return finding{
		Name:        strings.TrimSpace(source.Name),
		Host:        host,
		Port:        strings.TrimSpace(source.Port),
		Severity:    severity,
		Threat:      severityLabel(severity, source.Threat),
		Family:      strings.TrimSpace(source.NVT.Family),
		Description: description,
		Solution:    strings.TrimSpace(source.NVT.Solution),
		References:  formatReferences(source.NVT.References),
	}
}

func severityLabel(score float64, fallback string) string {
	switch {
	case score >= 9:
		return "Crítica"
	case score >= 7:
		return "Alta"
	case score >= 4:
		return "Média"
	case score > 0:
		return "Baixa"
	case strings.TrimSpace(fallback) != "":
		return strings.TrimSpace(fallback)
	default:
		return "Informativa"
	}
}

func descriptionFromTags(tags string) string {
	var parts []string
	for _, tag := range strings.Split(tags, "|") {
		key, value, ok := strings.Cut(tag, "=")
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		switch strings.TrimSpace(key) {
		case "insight", "impact", "affected", "vuldetect":
			parts = append(parts, strings.TrimSpace(value))
		}
	}
	return strings.Join(parts, "\n\n")
}

func formatReferences(refs []xmlReference) string {
	values := make([]string, 0, len(refs))
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		value := strings.TrimSpace(ref.ID)
		if value == "" {
			continue
		}
		if kind := strings.TrimSpace(ref.Type); kind != "" {
			value = kind + ": " + value
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	sort.Strings(values)
	return strings.Join(values, "\n")
}
