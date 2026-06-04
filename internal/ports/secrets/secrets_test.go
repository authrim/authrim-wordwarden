package secrets

import "testing"

func TestParseRef(t *testing.T) {
	ref, err := ParseRef("env:AUTHRIM_SECRET")
	if err != nil {
		t.Fatalf("ParseRef() error = %v", err)
	}
	if ref.Scheme != "env" || ref.Name != "AUTHRIM_SECRET" {
		t.Fatalf("ParseRef() = %#v", ref)
	}
}

func TestParseRefRejectsUnsupportedScheme(t *testing.T) {
	if _, err := ParseRef("vault:path/to/secret"); err == nil {
		t.Fatal("ParseRef() error = nil, want unsupported scheme")
	}
}
