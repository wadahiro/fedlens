package ui

import (
	"embed"
	"strings"
)

//go:embed static/*
var StaticFiles embed.FS

// InlineAssets returns the embedded stylesheets and scripts concatenated, for
// pages that must be self-contained — an export opens from the filesystem, where
// /static/* does not resolve.
//
// htmx is deliberately omitted: it is served to the live UI but no template uses
// an hx-* attribute, so shipping it would add ~50KB of dead weight to every
// exported file.
func InlineAssets() (css string, js string) {
	read := func(name string) string {
		b, err := StaticFiles.ReadFile("static/" + name)
		if err != nil {
			// The files are compiled into the binary, so a failure here means the
			// embed pattern and this list disagree — a build-time mistake.
			panic("ui: embedded asset missing: " + name)
		}
		return string(b)
	}

	var sb strings.Builder
	for _, name := range []string{"pico.min.css", "prism.min.css", "app.css"} {
		sb.WriteString(read(name))
		sb.WriteString("\n")
	}
	css = sb.String()

	sb.Reset()
	sb.WriteString(read("prism.min.js"))
	return css, sb.String()
}
