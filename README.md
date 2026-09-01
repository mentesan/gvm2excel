# gvm2excel

[![Go][workflow-badge]][workflow]

`gvm2excel` converts XML reports exported by Greenbone Vulnerability Management (GVM) into organized Microsoft Excel
workbooks. It groups findings by severity, preserves host and scanner information, and creates charts for risk
distribution and the most affected hosts.

## Features

- Reads GVM XML reports without modifying the source file.
- Sorts findings by CVSS score, from highest to lowest.
- Creates dedicated worksheets for each severity class.
- Includes scan errors and detailed host information.
- Adds filters, frozen headers, wrapped text, and readable column widths.
- Generates a color-coded 3D risk chart.
- Generates a 3D chart for the ten hosts with the most findings.
- Returns a non-zero exit status for invalid input or workbook generation errors.

## Generated workbook

| Worksheet | Contents |
| --- | --- |
| `Geral` | Overall totals and the color-coded 3D risk chart. |
| `Crítico` | Critical and high-severity findings. |
| `Médio` | Medium-severity findings. |
| `Baixo` | Low-severity findings. |
| `Alarm` | Findings classified as `Alarm` by GVM. |
| `Log` | Informational and `Log` findings. |
| `Debug` | Findings classified as `Debug` by GVM. |
| `Possíveis falhas` | Scanner errors and possible incomplete checks. |
| `Vulns por Host` | Findings grouped by host, including a 3D Top 10 chart. |
| `Hosts` | Host details reported by GVM. |

The worksheet names remain in Brazilian Portuguese for compatibility with existing reports and workflows.

## Requirements

- Go 1.25 or later.
- A GVM report exported in XML format.
- Microsoft Excel, LibreOffice Calc, or another application capable of opening `.xlsx` files.

## Installation

### Install with Go

```sh
go install github.com/mentesan/gvm2excel@latest
```

Go installs the executable in `$(go env GOPATH)/bin`. Ensure that directory is included in your `PATH`:

```sh
export PATH="$(go env GOPATH)/bin:$PATH"
```

Confirm the installation:

```sh
gvm2excel
```

The command should print its usage message and exit with a non-zero status because no input file was supplied.

### Build from source

```sh
git clone https://github.com/mentesan/gvm2excel.git
cd gvm2excel
go build -o gvm2excel .
```

Optionally install the local checkout:

```sh
go install .
```

## Usage

```text
gvm2excel input.xml [output.xlsx]
```

Convert a report and choose the output filename:

```sh
gvm2excel gvm-report.xml vulnerability-report.xlsx
```

Omit the output argument to create `report.xlsx` in the current directory:

```sh
gvm2excel gvm-report.xml
```

Paths containing spaces must be quoted:

```sh
gvm2excel "reports/weekly scan.xml" "exports/weekly report.xlsx"
```

The input and output paths must be different. If the output file already exists, it may be replaced, so choose the
destination carefully.

## Severity classification

| CVSS score | Classification | Detailed worksheet |
| --- | --- | --- |
| 9.0–10.0 | Critical | `Crítico` |
| 7.0–8.9 | High | `Crítico` |
| 4.0–6.9 | Medium | `Médio` |
| 0.1–3.9 | Low | `Baixo` |
| 0.0 or unavailable | GVM classification or informational | `Alarm`, `Log`, or `Debug` when applicable |

The `Geral` worksheet displays critical and high findings separately in the risk chart, while both remain in the
`Crítico` worksheet for compatibility with the original tool.

## Handling sensitive reports

GVM reports commonly contain IP addresses, hostnames, vulnerabilities, software versions, and other sensitive data.

- Process reports only on trusted systems.
- Store generated workbooks with the same protection as the source reports.
- Do not attach production reports to bug reports or pull requests.
- Sanitize examples before sharing them.
- XML and XLSX files are ignored by this repository's `.gitignore` by default.

The program performs all conversion locally and does not send report data to an external service.

## Limits and error handling

- The maximum accepted XML input size is 512 MiB.
- Malformed XML is rejected.
- XML files without recognizable GVM findings are rejected.
- Errors are written to standard error.
- Successful conversions exit with status `0`; failures exit with a non-zero status.

Example:

```text
gvm2excel: usage: gvm2excel input.xml [output.xlsx]
```

## Development

```sh
go mod download
go test ./...
go vet ./...
go build -o gvm2excel .
```

Tests use synthetic XML data only. Real customer or production reports must never be committed to the repository.

## License

This project is distributed under the BSD 3-Clause License. See [LICENSE](LICENSE).

[workflow]: https://github.com/mentesan/gvm2excel/actions/workflows/go.yml
[workflow-badge]: https://github.com/mentesan/gvm2excel/actions/workflows/go.yml/badge.svg
