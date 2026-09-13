package vkturncore

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"math/big"
)

// randIntN returns a uniform random int in [0, n).
func randIntN(n int) int {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

// randHex returns a random hex string of n bytes.
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// randFloat64 returns a random float64 in [0.0, 1.0).
func randFloat64() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	u := binary.LittleEndian.Uint64(b[:]) >> 11
	return float64(u) / float64(1<<53)
}
