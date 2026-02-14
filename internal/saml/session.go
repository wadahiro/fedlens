package saml

import (
	"net/http"
	"sync"
)

// DebugSessionStore is a per-SP in-memory debug session store.
type DebugSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*DebugSession
}

// NewDebugSessionStore creates a new debug session store.
func NewDebugSessionStore() *DebugSessionStore {
	return &DebugSessionStore{
		sessions: make(map[string]*DebugSession),
	}
}

// Get retrieves a debug session by the saml_debug_id cookie.
func (s *DebugSessionStore) Get(r *http.Request) *DebugSession {
	c, err := r.Cookie("saml_debug_id")
	if err != nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[c.Value]
}

// GetByID retrieves a debug session by ID.
func (s *DebugSessionStore) GetByID(id string) *DebugSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[id]
}

// Set stores a debug session with the given ID.
func (s *DebugSessionStore) Set(id string, session *DebugSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = session
}

// Delete removes a debug session by ID.
func (s *DebugSessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}
