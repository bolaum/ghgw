package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
)

// The master key is 32 random bytes (AES-256), written in standard base64 in the key file and in
// GHGW_MASTER_KEY.
const masterKeyBytes = 32

var errMalformedMasterKey = errors.New("want 32 bytes in standard base64, e.g. the output of: head -c 32 /dev/urandom | base64")

func newMasterKey() []byte {
	key := make([]byte, masterKeyBytes)
	_, _ = rand.Read(key) // never fails: crypto/rand aborts the program instead
	return key
}

func encodeMasterKey(key []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(key) + "\n")
}

// parseMasterKey decodes a master key. Surrounding white space is ignored. The error never quotes
// the input.
func parseMasterKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) != base64.StdEncoding.EncodedLen(masterKeyBytes) {
		return nil, errMalformedMasterKey
	}
	key, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(key) != masterKeyBytes {
		return nil, errMalformedMasterKey
	}
	return key, nil
}

// newAEAD returns AES-256-GCM under key with a random 96-bit nonce per Seal, prepended to the
// ciphertext. ghgw seals a handful of credentials per key, far below the 2^32 messages a random
// nonce allows.
func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// The additional authenticated data binds each ciphertext to its purpose and, for credentials, to
// its owner: a ciphertext copied to another owner's row, or used as the key check, fails to open.
// Owner names are compared case-insensitively, so the owner is bound in lowercase.
const (
	keyCheckAAD       = "ghgw key check"
	keyCheckPlaintext = "ghgw master key check"
)

func credentialAAD(owner string) []byte {
	return []byte("ghgw credential\x00" + strings.ToLower(owner))
}
