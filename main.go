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
		[]string{"violated_directive", "host"},
	)

	cspReportsErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "csp_reports_errors_total",
			Help: "Total number of errors processing CSP reports",
		},
	)
)

// CSPReport struct represents the CSP violation report
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
	// Получаем информацию о хосте
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}

	// Проверяем метод запроса
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

	// Декодируем JSON
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

	// Увеличиваем метрику
	cspReportsTotal.WithLabelValues(
		report.CSPReport.ViolatedDirective,
		host,
	).Inc()

	// Логируем отчет
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

func main() {
	// Инициализируем сервер
	server := NewServer()

	// Получаем порт из переменной окружения или используем порт по умолчанию
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Включаем метрики только если установлена соответствующая переменная окружения
	if os.Getenv("ENABLE_METRICS") == "true" {
		http.Handle("/metrics", promhttp.Handler())
		server.logger.Info("Prometheus metrics enabled at /metrics")
	}

	// Регистрируем обработчик для CSP отчетов
	http.HandleFunc("/report", server.handleCSPReport)

	server.logger.WithFields(logrus.Fields{
		"port": port,
	}).Info("Starting CSP report collector")

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		server.logger.WithError(err).Fatal("Server failed to start")
	}
}
