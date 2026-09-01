package main

import (
	"strings"
	"testing"
)

const syntheticReport = `<report><results>
<result><name>Older service</name><host><hostname>host-b.test</hostname>192.0.2.20</host><port>443/tcp</port>
<severity>5.0</severity><threat>Medium</threat><description>Example description</description>
<nvt><name>Older service</name><family>Service detection</family><solution>Update the service.</solution>
<refs><ref type="cve" id="CVE-2000-0001"/></refs></nvt></result>
<result><name>Critical example</name><host>192.0.2.10</host><port>22/tcp</port><severity>9.8</severity>
<nvt><name>Critical example</name><family>General</family><tags>impact=Example impact|affected=Example product</tags>
<solution>Apply the vendor update.</solution></nvt></result>
</results><errors><error><host>192.0.2.30</host><port>general/tcp</port>
<nvt><name>Scanner example</name><cvss_base>7.0</cvss_base></nvt></error></errors>
<host><ip>192.0.2.10</ip><detail><name>OS</name><value>Example OS</value><extra>80</extra>
<source><type>nvt</type><description>Synthetic detail</description></source></detail></host></report>`

func TestParseReport(t *testing.T) {
	parsed, err := parseReport(strings.NewReader(syntheticReport))
	if err != nil {
		t.Fatalf("parseReport() error = %v", err)
	}
	if len(parsed.Findings) != 2 {
		t.Fatalf("len(Findings) = %d, want 2", len(parsed.Findings))
	}
	if parsed.Findings[0].Name != "Critical example" {
		t.Errorf("first finding = %q, want highest severity first", parsed.Findings[0].Name)
	}
	if parsed.Findings[1].Host != "192.0.2.20 (host-b.test)" {
		t.Errorf("host = %q", parsed.Findings[1].Host)
	}
	if parsed.Findings[1].References != "cve: CVE-2000-0001" {
		t.Errorf("references = %q", parsed.Findings[1].References)
	}
	if len(parsed.Errors) != 1 || parsed.Errors[0].Name != "Scanner example" {
		t.Errorf("errors = %#v", parsed.Errors)
	}
	if len(parsed.Hosts) != 1 || len(parsed.Hosts[0].Details) != 1 {
		t.Errorf("hosts = %#v", parsed.Hosts)
	}
}

func TestParseReportRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "malformed", input: `<report>`},
		{name: "without findings", input: `<report><results/></report>`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseReport(strings.NewReader(test.input)); err == nil {
				t.Fatal("parseReport() error = nil, want error")
			}
		})
	}
}

func TestSeverityLabel(t *testing.T) {
	tests := []struct {
		score    float64
		fallback string
		want     string
	}{{9, "", "Crítica"}, {7, "", "Alta"}, {4, "", "Média"}, {0.1, "", "Baixa"}, {0, "Log", "Log"}}
	for _, test := range tests {
		if got := severityLabel(test.score, test.fallback); got != test.want {
			t.Errorf("severityLabel(%v, %q) = %q, want %q", test.score, test.fallback, got, test.want)
		}
	}
}
