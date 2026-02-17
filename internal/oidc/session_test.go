package oidc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestSessionStore(t *testing.T) {
	store := NewSessionStore()

	session := &Session{
		IDTokenRaw:      "id-token-raw",
		AccessTokenRaw:  "access-token-raw",
		RefreshTokenRaw: "refresh-token-raw",
	}

	t.Run("Set and GetByID", func(t *testing.T) {
		store.Set("sid1", session)
		got := store.GetByID("sid1")
		if got == nil {
			t.Fatal("expected session, got nil")
		}
		if got.IDTokenRaw != "id-token-raw" {
			t.Errorf("IDTokenRaw = %q, want id-token-raw", got.IDTokenRaw)
		}
	})

	t.Run("GetByID nonexistent", func(t *testing.T) {
		if got := store.GetByID("nonexistent"); got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})

	t.Run("Get with cookie", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: "session_id", Value: "sid1"})
		got := store.Get(r)
		if got == nil {
			t.Fatal("expected session, got nil")
		}
		if got.AccessTokenRaw != "access-token-raw" {
			t.Errorf("AccessTokenRaw = %q, want access-token-raw", got.AccessTokenRaw)
		}
	})

	t.Run("Get without cookie", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		got := store.Get(r)
		if got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		store.Delete("sid1")
		if got := store.GetByID("sid1"); got != nil {
			t.Errorf("expected nil after delete, got %+v", got)
		}
	})
}

func TestDebugSessionStore(t *testing.T) {
	store := NewDebugSessionStore()

	session := &DebugSession{
		Results: []ResultEntry{
			{Type: "Login"},
		},
	}

	t.Run("Set and GetByID", func(t *testing.T) {
		store.Set("did1", session)
		got := store.GetByID("did1")
		if got == nil {
			t.Fatal("expected session, got nil")
		}
		if len(got.Results) != 1 {
			t.Errorf("Results count = %d, want 1", len(got.Results))
		}
	})

	t.Run("Get with oidc_debug_id cookie", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: "oidc_debug_id", Value: "did1"})
		got := store.Get(r)
		if got == nil {
			t.Fatal("expected session, got nil")
		}
	})

	t.Run("Get without cookie", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		got := store.Get(r)
		if got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		store.Delete("did1")
		if got := store.GetByID("did1"); got != nil {
			t.Errorf("expected nil after delete, got %+v", got)
		}
	})
}

func TestSessionStoreConcurrency(t *testing.T) {
	store := NewSessionStore()
	var wg sync.WaitGroup

	for i := range 100 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := fmt.Sprintf("session-%d", id)
			store.Set(key, &Session{IDTokenRaw: key})
			store.GetByID(key)
			store.Delete(key)
		}(i)
	}

	wg.Wait()
}
