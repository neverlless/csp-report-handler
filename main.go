package main

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

var (
	// Prometheus metrics
	cspReportsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "csp_reports_total",
			Help: "Total number of CSP violation reports received",
		},
		[]string{"violated_directive", "host", "blocked_uri", "document_uri"},
	)

	cspReportsErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "csp_reports_errors_total",
			Help: "Total number of errors processing CSP reports",
		},
	)

	// Histogram for status codes
	cspReportsStatusCodes = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "csp_reports_status_codes",
			Help:    "Status codes distribution for CSP violation reports",
			Buckets: []float64{200, 300, 400, 500},
		},
		[]string{"host"},
	)

	// Metrics for referrers
	cspReportsReferrers = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "csp_reports_referrers_total",
			Help: "Total number of CSP violations by referrer",
		},
		[]string{"host", "referrer"},
	)

	// Metrics for blocked URIs
	cspReportsBlockedURIs = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "csp_reports_blocked_uris_total",
			Help: "Total number of blocked URIs by directive",
		},
		[]string{"host", "violated_directive", "blocked_uri"},
	)
)

// CSPReport structure for parsing CSP reports
type CSPReport struct {
	CSPReport struct {
		DocumentURI        string `json:"document-uri"`
		Referrer           string `json:"referrer"`
		ViolatedDirective  string `json:"violated-directive"`
		EffectiveDirective string `json:"effective-directive"`
		OriginalPolicy     string `json:"original-policy"`
		BlockedURI         string `json:"blocked-uri"`
		StatusCode         int    `json:"status-code"`
	} `json:"csp-report"`
}

type Server struct {
	logger *logrus.Logger
}

func NewServer() *Server {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(os.Stdout)

	return &Server{
		logger: logger,
	}
}

func (s *Server) handleCSPReport(w http.ResponseWriter, r *http.Request) {
	// Get the host from the request
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}

	// Check if the request method is POST
	if r.Method != http.MethodPost {
		s.logger.WithFields(logrus.Fields{
			"method": r.Method,
			"host":   host,
			"path":   r.URL.Path,
		}).Warn("Invalid request method")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		cspReportsErrors.Inc()
		return
	}

	// Decode the JSON body
	var report CSPReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		s.logger.WithFields(logrus.Fields{
			"error": err,
			"host":  host,
		}).Error("Failed to decode JSON")
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		cspReportsErrors.Inc()
		return
	}

	// Update all metrics
	cspReportsTotal.WithLabelValues(
		report.CSPReport.ViolatedDirective,
		host,
		report.CSPReport.BlockedURI,
		report.CSPReport.DocumentURI,
	).Inc()

	cspReportsStatusCodes.WithLabelValues(host).Observe(float64(report.CSPReport.StatusCode))

	if report.CSPReport.Referrer != "" {
		cspReportsReferrers.WithLabelValues(host, report.CSPReport.Referrer).Inc()
	}

	cspReportsBlockedURIs.WithLabelValues(
		host,
		report.CSPReport.ViolatedDirective,
		report.CSPReport.BlockedURI,
	).Inc()

	// Log the report
	s.logger.WithFields(logrus.Fields{
		"document_uri":       report.CSPReport.DocumentURI,
		"blocked_uri":        report.CSPReport.BlockedURI,
		"violated_directive": report.CSPReport.ViolatedDirective,
		"original_policy":    report.CSPReport.OriginalPolicy,
		"host":               host,
		"referrer":           report.CSPReport.Referrer,
		"status_code":        report.CSPReport.StatusCode,
	}).Info("CSP violation report received")

	w.WriteHeader(http.StatusOK)
}

func startMetricsServer(logger *logrus.Logger, metricsPort string) {
	metricsServer := &http.Server{
		Addr:    ":" + metricsPort,
		Handler: promhttp.Handler(),
	}

	logger.WithFields(logrus.Fields{
		"port": metricsPort,
	}).Info("Starting metrics server")

	if err := metricsServer.ListenAndServe(); err != nil {
		logger.WithError(err).Fatal("Metrics server failed to start")
	}
}

func main() {
	// Initialize the server
	server := NewServer()

	// Port for the main server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Separate port for metrics
	metricsPort := os.Getenv("METRICS_PORT")
	if metricsPort == "" {
		metricsPort = "9090"
	}

	// Start the metrics server in a separate goroutine
	if os.Getenv("ENABLE_METRICS") == "true" {
		go startMetricsServer(server.logger, metricsPort)
	}

	// Register the handler for CSP reports
	http.HandleFunc("/report", server.handleCSPReport)

	server.logger.WithFields(logrus.Fields{
		"port": port,
	}).Info("Starting CSP report collector")

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		server.logger.WithError(err).Fatal("Main server failed to start")
	}
}
