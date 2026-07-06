// Package ratelimit provides a per-IP token bucket rate limiter.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// Limiter implements a per-IP token bucket rate limiter.
// It uses a background goroutine to periodically refill tokens
// and a cleanup goroutine to evict stale entries.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64
	burst   int
	stopCh  chan struct{}
	stopped bool
}

// New creates a Limiter that allows up to burst tokens instantly
// and refills at rate tokens per second.
func New(rate float64, burst int) *Limiter {
	l := &Limiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		burst:   burst,
		stopCh:  make(chan struct{}),
	}
	go l.refillLoop()
	go l.cleanupLoop()
	return l
}

// refillLoop periodically adds tokens to all active buckets.
// Runs every 100ms.
func (l *Limiter) refillLoop() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	refill := l.rate * 0.1 // tokens per tick

	for {
		select {
		case <-ticker.C:
			l.mu.Lock()
			for _, b := range l.buckets {
				b.tokens += refill
				if b.tokens > float64(l.burst) {
					b.tokens = float64(l.burst)
				}
			}
			l.mu.Unlock()
		case <-l.stopCh:
			return
		}
	}
}

// cleanupLoop evicts IPs not seen in the last 10 minutes.
// Runs every minute.
func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l.mu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			for ip, b := range l.buckets {
				if b.lastSeen.Before(cutoff) {
					delete(l.buckets, ip)
				}
			}
			l.mu.Unlock()
		case <-l.stopCh:
			return
		}
	}
}

// Allow checks if a request from the given IP is allowed.
// It consumes one token on success.
func (l *Limiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[ip]
	if !ok {
		b = &bucket{tokens: float64(l.burst), lastSeen: time.Now()}
		l.buckets[ip] = b
	}

	b.lastSeen = time.Now()

	if b.tokens >= 1.0 {
		b.tokens--
		return true
	}
	return false
}

// Stop terminates the background goroutines. The limiter must not
// be used after Stop is called.
func (l *Limiter) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.stopped {
		l.stopped = true
		close(l.stopCh)
	}
}
