package mtproxy

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

func benchmarkSecrets(count int) [][16]byte {
	result := make([][16]byte, count)
	var encoded [8]byte
	for i := range result {
		binary.LittleEndian.PutUint64(encoded[:], uint64(i+1))
		sum := sha256.Sum256(encoded[:])
		copy(result[i][:], sum[:16])
	}
	return result
}

func BenchmarkReplayCache(b *testing.B) {
	now := time.Unix(1_700_000_000, 0)
	b.Run("Exact", func(b *testing.B) {
		cache, _ := NewReplayCache(65536, 10*time.Minute)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = cache.CheckAndAdd(replayKey(uint64(i)), now)
		}
	})
	b.Run("Bloom", func(b *testing.B) {
		cache, _ := NewBloomReplayCache(65536, 10*time.Minute)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = cache.CheckAndAdd(replayKey(uint64(i)), now)
		}
	})
}

func BenchmarkSecretProbe(b *testing.B) {
	counts := []int{1, 4, 8, 16, 32, 64, 128, 256, 1_000, 10_000, 100_000, 500_000}
	var invalidHeader [obfuscatedHeaderSize]byte
	for i := range invalidHeader {
		invalidHeader[i] = byte(i*37 + 11)
	}
	for _, count := range counts {
		b.Run(fmt.Sprintf("Invalid/%d", count), func(b *testing.B) {
			secrets := benchmarkSecrets(count)
			b.ReportAllocs()
			b.SetBytes(int64(count))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := AcceptObfuscatedHeader(invalidHeader, secrets); err == nil {
					b.Fatal("invalid header authenticated")
				}
			}
		})
	}
}
