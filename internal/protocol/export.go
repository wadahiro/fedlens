package protocol

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/wadahiro/fedlens/internal/ui"
	"github.com/wadahiro/fedlens/internal/ui/templates"
)

var exportNameUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// ApplyExportPage turns a PageInfo into one that renders as a standalone file.
// Assets are inlined because /static/* does not resolve from the filesystem, and
// every control that would post back to a server is cleared — an exported file
// is evidence, not a working UI.
func ApplyExportPage(page *templates.PageInfo) {
	page.InlineCSS, page.InlineJS = ui.InlineAssets()
	page.ExportedAt = FormatTimestamp(time.Now().UTC().Format(time.RFC3339))

	page.LoginURL = ""
	page.LoginOptions = nil
	page.ReauthOptions = nil
	page.LogoutOptions = nil
	page.LogoutURL = ""
	page.UserInfoURL = ""
	page.IntrospectionURL = ""
	page.RevokeAccessTokenURL = ""
	page.RevokeRefreshTokenURL = ""
	page.RefreshURL = ""
	page.ClearURL = ""
	page.ExportURL = ""
	page.ResourceAccessItems = nil

	// The app tabs link to the other SP/RP entries on this server. An export is
	// scoped to one of them and travels to other machines, so those links would
	// be dead — or worse, point at someone else's running instance. The header
	// still names the entry via ActiveTab.
	page.Tabs = nil
}

// ExportDisposition builds the Content-Disposition header for an export. The
// entry name comes from configuration, so it is reduced to a filename-safe form
// rather than trusted.
func ExportDisposition(name string) string {
	safe := strings.Trim(exportNameUnsafe.ReplaceAllString(name, "-"), "-")
	if safe == "" {
		safe = "fedlens"
	}
	return fmt.Sprintf("attachment; filename=%q", fmt.Sprintf("fedlens-%s-%s.html", safe, time.Now().UTC().Format("20060102-150405")))
}
