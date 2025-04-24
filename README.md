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

## Dashboard Preview

![CSP Violations Dashboard](docs/images/dashboard-preview.png)

## Quick Start

Launch the demo environment with Docker Compose:

```bash
docker-compose up -d
```

After startup, the following services will be available:

- CSP Report Handler: <http://localhost:8080/report>
- Prometheus: <http://localhost:9091>
- Grafana: [http://localhost:3000](http://localhost:3000)

Grafana credentials:

- Username: admin
- Password: admin

### Testing the Setup

Send a test CSP report:

```bash
curl -X POST http://localhost:8080/report \
  -H "Content-Type: application/csp-report" \
  -d '{
    "csp-report": {
      "document-uri": "https://example.com",
      "referrer": "https://example.com",
      "violated-directive": "script-src",
      "effective-directive": "script-src",
      "original-policy": "script-src '\''self'\''",
      "blocked-uri": "https://evil.com/script.js"
    }
  }'
```

Open Grafana (<http://localhost:3000>) and navigate to the pre-configured "CSP Violations Dashboard"

### Stopping the Environment

Stop all services:

```bash
docker-compose down
```

Remove all data including volumes:

```bash
docker-compose down -v
```

## Manual Installation

### Prerequisites

- Go 1.24.2 or higher
- Prometheus
- Grafana (optional, for visualization)

### Installation

```bash
git clone github.com/neverlless/csp-report-handler
cd csp-report-handler
go mod download
```

### Configuration

The application can be configured using environment variables:

- `PORT` - Main server port (default: 8080)
- `METRICS_PORT` - Prometheus metrics port (default: 9090)
- `ENABLE_METRICS` - Enable/disable metrics endpoint (default: false)

### Usage

1. Start the server:

```bash
go run main.go
```

1. Configure your web application's CSP report-uri:

```bash
Content-Security-Policy: ...; report-uri http://your-server:8080/report;
```

1. Access Prometheus metrics:

```bash
http://your-server:9090/metrics
```

## Available Metrics

The following Prometheus metrics are exposed:

- `csp_reports_total` - Total number of CSP violation reports
- `csp_reports_errors_total` - Total number of processing errors
- `csp_reports_status_codes` - Status codes distribution
- `csp_reports_referrers_total` - Violations by referrer
- `csp_reports_blocked_uris_total` - Blocked URIs by directive

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
