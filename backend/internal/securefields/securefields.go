// Package securefields provides authenticated encryption for database values.
package securefields

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const prefix = "enc:v1:"

type Protector struct{ aead cipher.AEAD }

func New(encodedKey string) (*Protector, error) {
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("RTM_FIELD_ENCRYPTION_KEY must be base64-encoded 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Protector{aead: aead}, nil
}

func IsSealed(value string) bool { return strings.HasPrefix(value, prefix) }

func (p *Protector) Seal(value string) (string, error) {
	if value == "" || IsSealed(value) {
		return value, nil
	}
	nonce := make([]byte, p.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	return prefix + base64.StdEncoding.EncodeToString(append(nonce, p.aead.Seal(nil, nonce, []byte(value), nil)...)), nil
}

func (p *Protector) Open(value string) (string, error) {
	if value == "" || !IsSealed(value) {
		return value, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil || len(raw) < p.aead.NonceSize() {
		return "", fmt.Errorf("invalid encrypted field")
	}
	plain, err := p.aead.Open(nil, raw[:p.aead.NonceSize()], raw[p.aead.NonceSize():], nil)
	if err != nil {
		return "", fmt.Errorf("decrypt field: %w", err)
	}
	return string(plain), nil
}
