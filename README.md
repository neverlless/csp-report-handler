# CSP Report Handler

A lightweight and efficient Content Security Policy (CSP) violation report collector with Prometheus metrics integration and Grafana dashboard visualization.

## Features

- Collects and processes CSP violation reports
- Exposes Prometheus metrics for monitoring
- Includes pre-configured Grafana dashboard
- JSON-formatted logging
- Support for multiple hosts/domains
- Tracks various CSP violation metrics:
  - Total violations by directive and host
  - Blocked URIs distribution
  - Status codes distribution
  - Top referrers
  - Error counts

## Prerequisites

- Go 1.24.2 or higher
- Prometheus
- Grafana (optional, for visualization)

## Installation

```bash
git clone github.com/neverlless/csp-report-handler
cd csp-report-handler
go mod download
```

## Configuration

The application can be configured using environment variables:

- `PORT` - Main server port (default: 8080)
- `METRICS_PORT` - Prometheus metrics port (default: 9090)
- `ENABLE_METRICS` - Enable/disable metrics endpoint (default: false)

## Usage

1. Start the server:

```bash
go run main.go
```

1. Configure your web application's CSP report-uri to point to the collector:

```bash
Content-Security-Policy: ...; report-uri http://your-server:8080/report;
```

1. Access Prometheus metrics at:

```bash
http://your-server:9090/metrics
```

## Metrics

The following Prometheus metrics are available:

- `csp_reports_total` - Total number of CSP violation reports
- `csp_reports_errors_total` - Total number of processing errors
- `csp_reports_status_codes` - Status codes distribution
- `csp_reports_referrers_total` - Violations by referrer
- `csp_reports_blocked_uris_total` - Blocked URIs by directive

## Grafana Dashboard

Import the provided `grafana-dashboard.json` to visualize:

- CSP Violations by Directive and Host
- Blocked URIs by Host
- Status Codes Distribution
- Top Referrers

## Docker Support

Build the image:

```bash
docker build -t csp-report-handler .
```

Run the container:

```bash
docker run -p 8080:8080 -p 9090:9090 \
  -e ENABLE_METRICS=true \
  csp-report-handler
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
