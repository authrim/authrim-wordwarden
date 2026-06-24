package app

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const instanceIDFileName = "instance_id"

var instanceIDPattern = regexp.MustCompile(`^wwi_[A-Za-z0-9_-]{22,64}$`)

func loadOrCreateInstanceID(stateDir string) (string, error) {
	if strings.TrimSpace(stateDir) == "" {
		return "", errors.New("state directory is required")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", fmt.Errorf("create state directory: %w", err)
	}
	path := filepath.Join(stateDir, instanceIDFileName)
	raw, err := os.ReadFile(path)
	if err == nil {
		value := strings.TrimSpace(string(raw))
		if !instanceIDPattern.MatchString(value) {
			return "", errors.New("stored instance_id is invalid")
		}
		return value, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read instance_id: %w", err)
	}
	value, err := generateInstanceID()
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write instance_id: %w", err)
	}
	return value, nil
}

func generateInstanceID() (string, error) {
	var randomBytes [16]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return "", fmt.Errorf("generate instance_id: %w", err)
	}
	return "wwi_" + base64.RawURLEncoding.EncodeToString(randomBytes[:]), nil
}
