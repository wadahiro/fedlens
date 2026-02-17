package saml

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestSAMLDebugSessionStore(t *testing.T) {
	store := NewDebugSessionStore()

	session := &DebugSession{
		Results: []SAMLResultEntry{
			{Type: "Login", Subject: "user@example.com"},
		},
	}

	t.Run("Set and GetByID", func(t *testing.T) {
		store.Set("sdid1", session)
		got := store.GetByID("sdid1")
		if got == nil {
			t.Fatal("expected session, got nil")
		}
		if len(got.Results) != 1 {
			t.Errorf("Results count = %d, want 1", len(got.Results))
		}
		if got.Results[0].Subject != "user@example.com" {
			t.Errorf("Subject = %q, want user@example.com", got.Results[0].Subject)
		}
	})

	t.Run("Get with saml_debug_id cookie", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: "saml_debug_id", Value: "sdid1"})
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

	t.Run("GetByID nonexistent", func(t *testing.T) {
		if got := store.GetByID("nonexistent"); got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		store.Delete("sdid1")
		if got := store.GetByID("sdid1"); got != nil {
			t.Errorf("expected nil after delete, got %+v", got)
		}
	})
}

func TestSAMLDebugSessionStoreConcurrency(t *testing.T) {
	store := NewDebugSessionStore()
	var wg sync.WaitGroup

	for i := range 100 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := fmt.Sprintf("saml-session-%d", id)
			store.Set(key, &DebugSession{
				Results: []SAMLResultEntry{{Type: "Login"}},
			})
			store.GetByID(key)
			store.Delete(key)
		}(i)
	}

	wg.Wait()
}
