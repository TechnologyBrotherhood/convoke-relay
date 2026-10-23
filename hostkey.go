package main

// Key-bound host ids. A host id of the form "k1" + 30 base64url characters is derived
// from the host's static X25519 public key, and the host proves it holds the private
// key on every connection. Such ids need no claim: nobody else can ever authenticate
// as them, before or after any expiry. (Other ids are claimed by a shared secret on
// first use; see ClaimStore.)
//
//   relay → host  {"t":"challenge","e":<b64u relay ephemeral X25519 public key>,"n":<b64u 32-byte nonce>}
//   host → relay  {"t":"auth","pub":<b64u host public key>,"proof":<b64u HMAC>}
//
// proof = HMAC-SHA256(key = X25519(host private, e), "convoke-relay-auth-v1" || id || n)

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

const keyIDPrefix = "k1"

var b64u = base64.RawURLEncoding

// hostIDFor derives the key-bound host id for a public key.
func hostIDFor(pub []byte) string {
	sum := sha256.Sum256(append([]byte("convoke-host-id-v1"), pub...))
	return keyIDPrefix + b64u.EncodeToString(sum[:])[:30]
}

// isKeyBoundID reports whether an id has the key-bound form (reserved: never claimable by secret).
func isKeyBoundID(id string) bool {
	return len(id) == 32 && strings.HasPrefix(id, keyIDPrefix)
}

// challenge is one connection's key-proof challenge.
type challenge struct {
	priv  *ecdh.PrivateKey
	nonce []byte
}

func newChallenge() (*challenge, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &challenge{priv: priv, nonce: nonce}, nil
}

func (c *challenge) frame() frame {
	return frame{T: "challenge", E: b64u.EncodeToString(c.priv.PublicKey().Bytes()), N: b64u.EncodeToString(c.nonce)}
}

// verify checks that pub derives id and proof shows possession of pub's private key.
func (c *challenge) verify(id, pubB64, proofB64 string) bool {
	pub, err := b64u.DecodeString(pubB64)
	if err != nil || hostIDFor(pub) != id {
		return false
	}
	proof, err := b64u.DecodeString(proofB64)
	if err != nil {
		return false
	}
	hostPub, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return false
	}
	shared, err := c.priv.ECDH(hostPub)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, shared)
	mac.Write([]byte("convoke-relay-auth-v1"))
	mac.Write([]byte(id))
	mac.Write(c.nonce)
	return hmac.Equal(mac.Sum(nil), proof)
}
