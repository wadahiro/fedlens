// Package store provides the in-memory maps backing session and debug state.
package store

import (
	"sync"
	"time"
)

// DefaultTTL is how long an entry survives without being touched. The debug
// timeline is meant to outlive individual logins, so this is generous; it exists
// to bound memory, not to expire sessions on a schedule.
const DefaultTTL = 24 * time.Hour

type entry[T any] struct {
	value      T
	lastAccess time.Time
}

// TTLMap is a concurrency-safe map whose entries expire after a period of
// inactivity. Reading an entry refreshes it, so an active session is never
// evicted. Expired entries are swept on write: growth only happens on write, so
// that is the only time a sweep is needed, and an idle map does no work at all.
type TTLMap[T any] struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]*entry[T]
	now     func() time.Time
}

// NewTTLMap creates a TTLMap. A non-positive ttl falls back to DefaultTTL.
func NewTTLMap[T any](ttl time.Duration) *TTLMap[T] {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &TTLMap[T]{
		ttl:     ttl,
		entries: make(map[string]*entry[T]),
		now:     time.Now,
	}
}

// Get returns the value stored under id and refreshes its expiry. The zero value
// and false are returned if the id is absent or has expired.
func (m *TTLMap[T]) Get(id string) (T, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.entries[id]
	if !ok {
		var zero T
		return zero, false
	}
	now := m.now()
	if now.Sub(e.lastAccess) > m.ttl {
		// Expired but not yet swept. Drop it now rather than serving it.
		delete(m.entries, id)
		var zero T
		return zero, false
	}
	e.lastAccess = now
	return e.value, true
}

// Set stores a value under id and sweeps expired entries.
func (m *TTLMap[T]) Set(id string, value T) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	for k, e := range m.entries {
		if now.Sub(e.lastAccess) > m.ttl {
			delete(m.entries, k)
		}
	}
	m.entries[id] = &entry[T]{value: value, lastAccess: now}
}

// Delete removes the entry stored under id.
func (m *TTLMap[T]) Delete(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, id)
}

// Len reports how many entries are held, including any that have expired but
// have not been swept yet.
func (m *TTLMap[T]) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}
