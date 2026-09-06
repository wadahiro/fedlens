package main

import "testing"

func TestVersionString(t *testing.T) {
	original := version
	t.Cleanup(func() { version = original })

	version = "v1.2.3"
	if got := versionString(); got != "v1.2.3" {
		t.Errorf("versionString() = %q, want the linker-stamped value", got)
	}

	// Without a stamped value it falls back to the embedded build info. The
	// exact value depends on how the test binary was built, but it must never
	// be empty — the version is logged at startup and printed by --version.
	version = ""
	if got := versionString(); got == "" {
		t.Error("versionString() returned an empty string with no stamped version")
	}
}
