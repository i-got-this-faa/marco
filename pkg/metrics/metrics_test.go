package metrics

import "testing"

func TestNewRegistry(t *testing.T) {
	reg := NewRegistry()
	if reg == nil {
		t.Fatal("NewRegistry returned nil")
	}
}

func TestRegistryIncrements(t *testing.T) {
	reg := NewRegistry()

	reg.SMTPConnections.Inc()
	reg.MessagesReceived.Inc()
	reg.MessagesDelivered.Inc()
	reg.ActiveConnections.Set(5)
	reg.QueuePending.Set(3)
	reg.QueueRetriesTotal.Inc()
	reg.IMAPSessions.Inc()
	reg.MessagesBounced.Inc()
}

func TestSMTPErrorsVec(t *testing.T) {
	reg := NewRegistry()
	reg.SMTPErrors.WithLabelValues("auth").Inc()
	reg.SMTPErrors.WithLabelValues("timeout").Inc()
	reg.SMTPErrors.WithLabelValues("timeout").Inc()
}

func TestRegistryMultipleInstances(t *testing.T) {
	// Should not panic.
	r1 := NewRegistry()
	r2 := NewRegistry()
	r1.SMTPConnections.Inc()
	r2.IMAPSessions.Inc()
}

func TestActiveConnectionsGauge(t *testing.T) {
	reg := NewRegistry()
	reg.ActiveConnections.Set(1)
	reg.ActiveConnections.Set(2)
	reg.ActiveConnections.Dec()
}

func TestQueuePendingGauge(t *testing.T) {
	reg := NewRegistry()
	reg.QueuePending.Set(10)
	reg.QueuePending.Dec()
	reg.QueuePending.Set(5)
}
