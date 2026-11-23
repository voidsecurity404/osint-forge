package scan

import (
	"encoding/base64"
	"math/bits"
)

// murmur3x86_32 implements MurmurHash3 (x86, 32-bit), returning the signed
// 32-bit value Shodan and Censys use for favicon hashes.
func murmur3x86_32(data []byte) int32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)
	var h uint32
	n := len(data)
	nblocks := n / 4
	for i := 0; i < nblocks; i++ {
		k := uint32(data[i*4]) | uint32(data[i*4+1])<<8 |
			uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}
	var k1 uint32
	tail := data[nblocks*4:]
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2
		h ^= k1
	}
	h ^= uint32(n)
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return int32(h)
}

// faviconHash reproduces Shodan's http.favicon.hash: mmh3 of the favicon bytes
// after Python-style base64 encoding (76-char lines, trailing newline).
func faviconHash(favicon []byte) int32 {
	enc := base64.StdEncoding.EncodeToString(favicon)
	var b []byte
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		b = append(b, enc[i:end]...)
		b = append(b, '\n')
	}
	return murmur3x86_32(b)
}
