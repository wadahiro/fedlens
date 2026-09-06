package oidc

import (
	"net/http"

	"github.com/wadahiro/fedlens/internal/store"
)

// SessionStore is a per-SP in-memory auth session store. Entries expire after a
// period of inactivity so that abandoned sessions do not hold their tokens for
// the life of the process.
type SessionStore struct {
	entries *store.TTLMap[*Session]
}

// NewSessionStore creates a new session store.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		entries: store.NewTTLMap[*Session](store.DefaultTTL),
	}
}

// Get retrieves a session by the session_id cookie.
func (s *SessionStore) Get(r *http.Request) *Session {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil
	}
	return s.GetByID(cookie.Value)
}

// Set stores a session with the given ID.
func (s *SessionStore) Set(id string, session *Session) {
	s.entries.Set(id, session)
}

// GetByID retrieves a session by ID.
func (s *SessionStore) GetByID(id string) *Session {
	session, ok := s.entries.Get(id)
	if !ok {
		return nil
	}
	return session
}

// Delete removes a session by ID.
func (s *SessionStore) Delete(id string) {
	s.entries.Delete(id)
}

// Len reports how many sessions are held. Used by tests.
func (s *SessionStore) Len() int {
	return s.entries.Len()
}

// DebugSessionStore is a per-SP in-memory debug session store. Entries expire on
// the same terms as SessionStore.
type DebugSessionStore struct {
	entries *store.TTLMap[*DebugSession]
}

// NewDebugSessionStore creates a new debug session store.
func NewDebugSessionStore() *DebugSessionStore {
	return &DebugSessionStore{
		entries: store.NewTTLMap[*DebugSession](store.DefaultTTL),
	}
}

// Get retrieves a debug session by the oidc_debug_id cookie.
func (s *DebugSessionStore) Get(r *http.Request) *DebugSession {
	c, err := r.Cookie("oidc_debug_id")
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
