package oidc

import (
	"net/http"
	"sync"
)

// SessionStore is a per-SP in-memory auth session store.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewSessionStore creates a new session store.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
	}
}

// Get retrieves a session by the session_id cookie.
func (s *SessionStore) Get(r *http.Request) *Session {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[cookie.Value]
}

// Set stores a session with the given ID.
func (s *SessionStore) Set(id string, session *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = session
}

// GetByID retrieves a session by ID.
func (s *SessionStore) GetByID(id string) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[id]
}

// Delete removes a session by ID.
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

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

// Get retrieves a debug session by the oidc_debug_id cookie.
func (s *DebugSessionStore) Get(r *http.Request) *DebugSession {
	c, err := r.Cookie("oidc_debug_id")
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
