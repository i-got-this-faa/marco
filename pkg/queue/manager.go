package queue

import (
	"context"
	"database/sql"
	"log/slog"
	"sync"
	"time"

	"github.com/i-got-this-faa/marco/pkg/blobstore"
	"github.com/i-got-this-faa/marco/pkg/dkim"
	"github.com/i-got-this-faa/marco/pkg/metrics"
	"github.com/i-got-this-faa/marco/pkg/storage"
)

// Manager handles outbound message delivery with retries and backoff.
type Manager struct {
	db         *sql.DB
	blob       blobstore.Store
	dkim       *dkim.Signer
	workers    int
	maxRetries int
	interval   time.Duration
	ipVersion  string
	log        *slog.Logger
	metrics    *metrics.Registry
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

func NewManager(db *sql.DB, blob blobstore.Store, workers, maxRetries int, interval time.Duration, ipVersion string) *Manager {
	return &Manager{
		db:         db,
		blob:       blob,
		workers:    workers,
		maxRetries: maxRetries,
		interval:   interval,
		ipVersion:  ipVersion,
		log:        slog.With("service", "queue"),
		metrics:    metrics.NewRegistry(),
		stopCh:     make(chan struct{}),
	}
}

// Enqueue adds a delivery task for a message to a recipient.
func (m *Manager) Enqueue(msgID int64, rcptTo string) error {
	if err := storage.Enqueue(context.Background(), m.db, msgID, rcptTo); err != nil {
		return err
	}
	m.metrics.QueuePending.Inc()
	return nil
}

// Start launches worker goroutines.
func (m *Manager) Start(ctx context.Context) error {
	m.log.Info("queue manager starting", "workers", m.workers)
	for range m.workers {
		m.wg.Add(1)
		go m.worker(ctx)
	}
	return nil
}

// Stop signals a graceful shutdown.
func (m *Manager) Stop() {
	close(m.stopCh)
	m.wg.Wait()
	m.log.Info("queue manager stopped")
}
