package util

import (
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand"
	"time"
)

const letters = "abcdefghijklmnpqrstuvwxyz"

// RandomAlphaString returns a random alphanumeric string consisting of `length` characters.
// Note the shared math/Rand source should be seeded.
func RandomAlphaString(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[mrand.Intn(len(letters))]
	}
	return string(b)
}

func init() {
	mrand.Seed(time.Now().UnixNano())
}

// RandInt64 returns a cryptographically secure random number within the bounds 0, max.
func RandInt64(max int64) int64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return int64(binary.LittleEndian.Uint64(b[:]))
}

// RandUint32 generates a cryptographically secure integer
func RandUint32() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b[:])
}
