package templates

import (
	"context"
	"strings"
	"testing"
)

// The request options script is delegated: each handler is registered once for
// the whole page. A second copy would run every click twice, so a caret would
// open its form and close it again in the same click.
func TestLayoutRegistersRequestOptionsHandlersOnce(t *testing.T) {
	var sb strings.Builder
	if err := Layout("t", PageInfo{}).Render(context.Background(), &sb); err != nil {
		t.Fatal(err)
	}
	html := sb.String()

	for _, marker := range []string{
		"function renderRequestOptions",
		"function saveRequestOptions",
		"function restoreRequestOptions",
		`closest(".split-caret`,
		`closest("form.request-options-form")`,
	} {
		if n := strings.Count(html, marker); n != 1 {
			t.Errorf("%q appears %d times in the layout script, want exactly 1", marker, n)
		}
	}
}
