package securefields

import (
	"encoding/base64"
	"testing"
)

func TestSealOpenAndLegacyValues(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	p, err := New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sealed, err := p.Seal("tenant-secret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if sealed == "tenant-secret" || !IsSealed(sealed) {
		t.Fatalf("sealed = %q", sealed)
	}
	plain, err := p.Open(sealed)
	if err != nil || plain != "tenant-secret" {
		t.Fatalf("Open = %q, %v", plain, err)
	}
	legacy, err := p.Open("legacy-plaintext")
	if err != nil || legacy != "legacy-plaintext" {
		t.Fatalf("legacy Open = %q, %v", legacy, err)
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	other := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz012345"))
	p, _ := New(key)
	q, _ := New(other)
	sealed, _ := p.Seal("tenant-secret")
	if _, err := q.Open(sealed); err == nil {
		t.Fatal("Open accepted wrong key")
	}
}
