package saml

import (
	"net/http"

	"github.com/wadahiro/fedlens/internal/store"
)

// DebugSessionStore is a per-SP in-memory debug session store. Entries expire
// after a period of inactivity so that abandoned flows — a closed browser, an
// expired cookie — do not hold their SAML XML for the life of the process.
type DebugSessionStore struct {
	entries *store.TTLMap[*DebugSession]
}

// NewDebugSessionStore creates a new debug session store.
func NewDebugSessionStore() *DebugSessionStore {
	return &DebugSessionStore{
		entries: store.NewTTLMap[*DebugSession](store.DefaultTTL),
	}
}

// Get retrieves a debug session by the saml_debug_id cookie.
func (s *DebugSessionStore) Get(r *http.Request) *DebugSession {
	c, err := r.Cookie("saml_debug_id")
	if err != nil {
		return nil
	}
	return s.GetByID(c.Value)
}

// GetByID retrieves a debug session by ID.
func (s *DebugSessionStore) GetByID(id string) *DebugSession {
	session, ok := s.entries.Get(id)
	if !ok {
		return nil
	}
	return session
}

// Set stores a debug session with the given ID.
func (s *DebugSessionStore) Set(id string, session *DebugSession) {
	s.entries.Set(id, session)
}

// Delete removes a debug session by ID.
func (s *DebugSessionStore) Delete(id string) {
	s.entries.Delete(id)
}

// Len reports how many debug sessions are held. Used by tests.
func (s *DebugSessionStore) Len() int {
	return s.entries.Len()
}
