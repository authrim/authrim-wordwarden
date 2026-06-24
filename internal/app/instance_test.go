package app

import "testing"

func TestLoadOrCreateInstanceIDPersistsGeneratedID(t *testing.T) {
	stateDir := t.TempDir()
	first, err := loadOrCreateInstanceID(stateDir)
	if err != nil {
		t.Fatalf("loadOrCreateInstanceID() error = %v", err)
	}
	if !instanceIDPattern.MatchString(first) {
		t.Fatalf("instance_id = %q", first)
	}
	second, err := loadOrCreateInstanceID(stateDir)
	if err != nil {
		t.Fatalf("loadOrCreateInstanceID() second error = %v", err)
	}
	if first != second {
		t.Fatalf("instance_id changed: first=%q second=%q", first, second)
	}
}
