package store

import (
	"testing"
	"time"
)

// newTestMap returns a TTLMap whose clock is driven by the returned pointer, so
// expiry can be exercised without sleeping.
func newTestMap[T any](ttl time.Duration) (*TTLMap[T], *time.Time) {
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m := NewTTLMap[T](ttl)
	m.now = func() time.Time { return clock }
	return m, &clock
}

func TestTTLMapGetSetDelete(t *testing.T) {
	m, _ := newTestMap[string](time.Hour)

	if _, ok := m.Get("missing"); ok {
		t.Error("Get on empty map returned ok")
	}

	m.Set("a", "value")
	got, ok := m.Get("a")
	if !ok || got != "value" {
		t.Errorf(`Get("a") = %q, %v; want "value", true`, got, ok)
	}

	m.Delete("a")
	if _, ok := m.Get("a"); ok {
		t.Error("Get after Delete returned ok")
	}
}

func TestTTLMapExpiresOnRead(t *testing.T) {
	m, clock := newTestMap[string](time.Hour)
	m.Set("a", "value")

	*clock = clock.Add(2 * time.Hour)

	if _, ok := m.Get("a"); ok {
		t.Error("expired entry was returned")
	}
	if n := m.Len(); n != 0 {
		t.Errorf("Len after expired read = %d, want 0", n)
	}
}

func TestTTLMapReadRefreshesExpiry(t *testing.T) {
	m, clock := newTestMap[string](time.Hour)
	m.Set("a", "value")

	// Touch the entry every 30 minutes over a span far beyond the TTL.
	for range 10 {
		*clock = clock.Add(30 * time.Minute)
		if _, ok := m.Get("a"); !ok {
			t.Fatal("active entry was expired")
		}
	}
}

func TestTTLMapSetSweepsExpired(t *testing.T) {
	m, clock := newTestMap[string](time.Hour)
	m.Set("old1", "v")
	m.Set("old2", "v")

	*clock = clock.Add(2 * time.Hour)
	m.Set("fresh", "v")

	if n := m.Len(); n != 1 {
		t.Errorf("Len after sweep = %d, want 1 (only the fresh entry)", n)
	}
	if _, ok := m.Get("fresh"); !ok {
		t.Error("fresh entry was swept")
	}
}

func TestNewTTLMapRejectsNonPositiveTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Minute} {
		if got := NewTTLMap[string](ttl).ttl; got != DefaultTTL {
			t.Errorf("NewTTLMap(%v).ttl = %v, want %v", ttl, got, DefaultTTL)
		}
	}
}

func TestTTLMapConcurrentAccess(t *testing.T) {
	m := NewTTLMap[int](time.Hour)
	done := make(chan struct{})

	for i := range 8 {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := range 100 {
				id := string(rune('a' + (i+j)%8))
				m.Set(id, j)
				m.Get(id)
				m.Len()
			}
		}()
	}
	for range 8 {
		<-done
	}
}
