package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Registry wraps Prometheus metric collectors for the mail server.
// It uses its own prometheus.Registerer to avoid test-time conflicts.
type Registry struct {
	SMTPConnections   prometheus.Counter
	SMTPErrors        *prometheus.CounterVec
	IMAPSessions      prometheus.Counter
	IMAPErrors        prometheus.Counter
	MessagesReceived  prometheus.Counter
	MessagesDelivered prometheus.Counter
	MessagesBounced   prometheus.Counter
	QueuePending      prometheus.Gauge
	QueueRetriesTotal prometheus.Counter
	ActiveConnections prometheus.Gauge

	registerer prometheus.Registerer
}

// NewRegistry creates and registers all metrics with a custom registry.
func NewRegistry() *Registry {
	r := &Registry{registerer: prometheus.NewRegistry()}
	f := prometheus.WrapRegistererWith(nil, r.registerer)

	r.SMTPConnections = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "marco_smtp_connections_total",
		Help: "Total SMTP connections accepted",
	})
	f.MustRegister(r.SMTPConnections)

	r.SMTPErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "marco_smtp_errors_total",
		Help: "SMTP errors by type",
	}, []string{"type"})
	f.MustRegister(r.SMTPErrors)

	r.IMAPSessions = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "marco_imap_sessions_total",
		Help: "Total IMAP sessions",
	})
	f.MustRegister(r.IMAPSessions)

	r.IMAPErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "marco_imap_errors_total",
		Help: "Total IMAP errors",
	})
	f.MustRegister(r.IMAPErrors)

	r.MessagesReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "marco_messages_received_total",
		Help: "Messages received via SMTP",
	})
	f.MustRegister(r.MessagesReceived)

	r.MessagesDelivered = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "marco_messages_delivered_total",
		Help: "Messages delivered to local mailboxes",
	})
	f.MustRegister(r.MessagesDelivered)

	r.MessagesBounced = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "marco_messages_bounced_total",
		Help: "Messages bounced / NDR sent",
	})
	f.MustRegister(r.MessagesBounced)

	r.QueuePending = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "marco_queue_pending",
		Help: "Currently pending outbound messages",
	})
	f.MustRegister(r.QueuePending)

	r.QueueRetriesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "marco_queue_retries_total",
		Help: "Total outbound delivery retries",
	})
	f.MustRegister(r.QueueRetriesTotal)

	r.ActiveConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "marco_active_connections",
		Help: "Currently active connections",
	})
	f.MustRegister(r.ActiveConnections)

	return r
}
