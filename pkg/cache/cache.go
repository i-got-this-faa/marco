// Package cache provides a generic, goroutine-safe TTL cache.
package cache

import (
	"sync"
	"time"
)

type entry[V any] struct {
	val      V
	expiresAt time.Time
}

// Cache is a generic, goroutine-safe TTL cache.
type Cache[K comparable, V any] struct {
	entries map[K]*entry[V]
	ttl     time.Duration
	maxSize int
	mu      sync.RWMutex
}

// New creates a new Cache. When ttl is zero, entries never expire.
// When maxSize is ≤ 0, the cache has no size limit.
func New[K comparable, V any](ttl time.Duration, maxSize int) *Cache[K, V] {
	return &Cache[K, V]{
		entries: make(map[K]*entry[V]),
		ttl:     ttl,
		maxSize: maxSize,
	}
}

// Get returns the value for key and a boolean indicating whether it was found.
// Expired entries are treated as missing (lazy eviction).
func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		var zero V
		return zero, false
	}
	if c.ttl > 0 && time.Now().After(e.expiresAt) {
		c.mu.Lock()
		// Double-check after acquiring write lock.
		if e, ok := c.entries[key]; ok && c.ttl > 0 && time.Now().After(e.expiresAt) {
			delete(c.entries, key)
		}
		c.mu.Unlock()
		var zero V
		return zero, false
	}
	return e.val, true
}

// Set adds or updates a value in the cache with the TTL configured at creation.
func (c *Cache[K, V]) Set(key K, val V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.maxSize > 0 && len(c.entries) >= c.maxSize {
		c.evictOne()
	}

	var expiresAt time.Time
	if c.ttl > 0 {
		expiresAt = time.Now().Add(c.ttl)
	}
	c.entries[key] = &entry[V]{val: val, expiresAt: expiresAt}
}

// Delete removes a key from the cache.
func (c *Cache[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// Clear removes all entries from the cache.
func (c *Cache[K, V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.entries)
}

// evictOne removes one entry when the cache is full. It tries to evict an
// expired entry first; if none are expired, it evicts a random entry.
// Must be called with c.mu held.
func (c *Cache[K, V]) evictOne() {
	for k, e := range c.entries {
		if c.ttl > 0 && time.Now().After(e.expiresAt) {
			delete(c.entries, k)
			return
		}
	}
	// No expired entry found; evict a random key.
	for k := range c.entries {
		delete(c.entries, k)
		return
	}
}

// Len returns the number of entries in the cache.
func (c *Cache[K, V]) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Keys returns a slice of all keys in the cache.
func (c *Cache[K, V]) Keys() []K {
	c.mu.RLock()
	defer c.mu.RUnlock()
	keys := make([]K, 0, len(c.entries))
	for k := range c.entries {
		keys = append(keys, k)
	}
	return keys
}
