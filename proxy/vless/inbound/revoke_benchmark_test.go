package inbound

import (
	"context"
	"strconv"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
)

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func newBenchmarkUsers(b *testing.B, count int) (*vless.MemoryValidator, []*protocol.MemoryUser) {
	b.Helper()
	validator := new(vless.MemoryValidator)
	users := make([]*protocol.MemoryUser, count)
	for i := range users {
		id := uuid.New()
		account, err := (&vless.Account{Id: id.String()}).AsAccount()
		if err != nil {
			b.Fatal(err)
		}
		users[i] = &protocol.MemoryUser{Email: "user" + strconv.Itoa(i) + "@example.com", Account: account}
		if err := validator.Add(users[i]); err != nil {
			b.Fatal(err)
		}
	}
	validator.Warmup()
	return validator, users
}

// BenchmarkProcessTracksConnection measures what Process adds per
// authenticated connection to make it revocable: the context, the lookup in
// the real validator and the registry insert and removal. The parent is a
// cancelable context, like the one the proxyman worker passes.
func BenchmarkProcessTracksConnection(b *testing.B) {
	for _, count := range []int{1, 10000} {
		b.Run("users="+strconv.Itoa(count), func(b *testing.B) {
			validator, users := newBenchmarkUsers(b, count)
			handler := &Handler{validator: validator}
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				parent, cancel := context.WithCancel(context.Background())
				_, tracked, err := handler.connections.Track(parent, handler.validator, users[i%count], nopCloser{})
				if err != nil {
					b.Fatal(err)
				}
				tracked.Release()
				cancel()
				i++
			}
		})
	}
}

// BenchmarkProcessWorkerContext is the control for
// BenchmarkProcessTracksConnection: the worker's own context alone.
func BenchmarkProcessWorkerContext(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_, cancel := context.WithCancel(context.Background())
		cancel()
	}
}

func BenchmarkProcessTracksConnectionParallel(b *testing.B) {
	validator, users := newBenchmarkUsers(b, 1024)
	handler := &Handler{validator: validator}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			parent, cancel := context.WithCancel(context.Background())
			_, tracked, err := handler.connections.Track(parent, handler.validator, users[i%len(users)], nopCloser{})
			if err != nil {
				b.Error(err)
				cancel()
				return
			}
			tracked.Release()
			cancel()
			i += 7
		}
	})
}
