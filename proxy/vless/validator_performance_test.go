package vless

import (
	"fmt"
	"runtime"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

var validatorUserSink *protocol.MemoryUser
var validatorUsersSink []*protocol.MemoryUser
var validatorCountSink int64

func benchmarkValidator(b *testing.B, users int) (*MemoryValidator, uuid.UUID) {
	b.Helper()
	validator := new(MemoryValidator)
	var target uuid.UUID
	for i := 0; i < users; i++ {
		id := uuid.UUID{15: byte(i + 1), 14: byte(i >> 8)}
		user := &protocol.MemoryUser{
			Email:   fmt.Sprintf("user-%d@example.com", i),
			Account: &MemoryAccount{ID: protocol.NewID(id)},
		}
		if err := validator.Add(user); err != nil {
			b.Fatal(err)
		}
		target = id
	}
	return validator, target
}

func BenchmarkMemoryValidatorGet(b *testing.B) {
	validator, target := benchmarkValidator(b, 1024)
	b.ReportAllocs()
	for b.Loop() {
		validatorUserSink = validator.Get(target)
	}
}

func BenchmarkMemoryValidatorSingleUserGet(b *testing.B) {
	validator, target := benchmarkValidator(b, 1)
	validator.Warmup()
	b.ReportAllocs()
	for b.Loop() {
		validatorUserSink = validator.Get(target)
	}
}

func BenchmarkMemoryValidatorEmptyGet(b *testing.B) {
	validator := new(MemoryValidator)
	validator.Warmup()
	target := uuid.UUID{15: 1}
	b.ReportAllocs()
	for b.Loop() {
		validatorUserSink = validator.Get(target)
	}
}

func BenchmarkMemoryValidatorGetParallel(b *testing.B) {
	validator, target := benchmarkValidator(b, 1024)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		var user *protocol.MemoryUser
		for pb.Next() {
			user = validator.Get(target)
		}
		runtime.KeepAlive(user)
	})
}

func BenchmarkMemoryValidatorColdGet(b *testing.B) {
	validator, target := benchmarkValidator(b, 1024)
	b.ReportAllocs()
	for b.Loop() {
		validator.userGeneration.Add(1)
		validatorUserSink = validator.Get(target)
	}
}

func BenchmarkMemoryValidatorWarmedGet(b *testing.B) {
	validator, target := benchmarkValidator(b, 1024)
	validator.Warmup()
	b.ReportAllocs()
	for b.Loop() {
		validatorUserSink = validator.Get(target)
	}
}

func BenchmarkMemoryValidatorGetAfterDynamicAdd(b *testing.B) {
	validator, target := benchmarkValidator(b, 1024)
	validator.Warmup()
	user := &protocol.MemoryUser{Account: &MemoryAccount{ID: protocol.NewID(target)}}
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		if err := validator.Add(user); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		validatorUserSink = validator.Get(target)
	}
}

func BenchmarkMemoryValidatorReplaceUser(b *testing.B) {
	validator := new(MemoryValidator)
	id := uuid.UUID{15: 1}
	user := &protocol.MemoryUser{Account: &MemoryAccount{ID: protocol.NewID(id)}}
	if err := validator.Add(user); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if err := validator.Add(user); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMemoryValidatorDeleteAndReaddUser(b *testing.B) {
	validator := new(MemoryValidator)
	id := uuid.UUID{15: 1}
	user := &protocol.MemoryUser{Email: "user@example.com", Account: &MemoryAccount{ID: protocol.NewID(id)}}
	if err := validator.Add(user); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if err := validator.Del(user.Email); err != nil {
			b.Fatal(err)
		}
		if err := validator.Add(user); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMemoryValidatorGetAll(b *testing.B) {
	validator, _ := benchmarkValidator(b, 1024)
	b.ReportAllocs()
	for b.Loop() {
		validatorUsersSink = validator.GetAll()
	}
}

func BenchmarkMemoryValidatorGetCount(b *testing.B) {
	validator, _ := benchmarkValidator(b, 1024)
	b.ReportAllocs()
	for b.Loop() {
		validatorCountSink = validator.GetCount()
	}
}

func BenchmarkMemoryValidatorGetAllWithoutEmails(b *testing.B) {
	validator := new(MemoryValidator)
	for i := 0; i < 1024; i++ {
		id := uuid.UUID{15: byte(i + 1), 14: byte(i >> 8)}
		if err := validator.Add(&protocol.MemoryUser{Account: &MemoryAccount{ID: protocol.NewID(id)}}); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	for b.Loop() {
		validatorUsersSink = validator.GetAll()
	}
}

func BenchmarkMemoryValidatorGetByEmail(b *testing.B) {
	validator, _ := benchmarkValidator(b, 1024)
	validator.Warmup()
	b.ReportAllocs()
	for b.Loop() {
		validatorUserSink = validator.GetByEmail("user-1023@example.com")
	}
}

func TestMemoryValidatorSnapshotTracksAddAndDelete(t *testing.T) {
	validator := new(MemoryValidator)
	firstID := uuid.UUID{15: 1}
	first := &protocol.MemoryUser{Email: "first@example.com", Account: &MemoryAccount{ID: protocol.NewID(firstID)}}
	if err := validator.Add(first); err != nil {
		t.Fatal(err)
	}
	if got := validator.Get(firstID); got == nil {
		t.Fatal("initial user lookup failed")
	}
	secondID := uuid.UUID{14: 1, 15: 2}
	second := &protocol.MemoryUser{Email: "second@example.com", Account: &MemoryAccount{ID: protocol.NewID(secondID)}}
	if err := validator.Add(second); err != nil {
		t.Fatal(err)
	}
	if got := validator.Get(secondID); got != second {
		t.Fatalf("new user lookup = %p, want %p", got, second)
	}
	if err := validator.Del(second.Email); err != nil {
		t.Fatal(err)
	}
	if got := validator.Get(secondID); got != nil {
		t.Fatalf("deleted user lookup = %p, want nil", got)
	}
}

func TestMemoryValidatorSnapshotConcurrentUpdates(t *testing.T) {
	validator := new(MemoryValidator)
	id := uuid.UUID{15: 9}
	user := &protocol.MemoryUser{Email: "concurrent@example.com", Account: &MemoryAccount{ID: protocol.NewID(id)}}
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}
	_ = validator.Get(id) // Build the initial snapshot before readers race with updates.

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 8 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = validator.Get(id)
				}
			}
		}()
	}
	for range 100 {
		if err := validator.Del(user.Email); err != nil {
			t.Fatal(err)
		}
		if err := validator.Add(user); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	readers.Wait()
	if got := validator.Get(id); got != user {
		t.Fatalf("final user lookup = %p, want %p", got, user)
	}
}

func TestMemoryValidatorCountTracksOnlyEmailUsers(t *testing.T) {
	validator := new(MemoryValidator)
	withEmail := &protocol.MemoryUser{Email: "counted@example.com", Account: &MemoryAccount{ID: protocol.NewID(uuid.UUID{15: 1})}}
	withoutEmail := &protocol.MemoryUser{Account: &MemoryAccount{ID: protocol.NewID(uuid.UUID{15: 2})}}
	if err := validator.Add(withEmail); err != nil {
		t.Fatal(err)
	}
	if err := validator.Add(withoutEmail); err != nil {
		t.Fatal(err)
	}
	if got := validator.GetCount(); got != 1 {
		t.Fatalf("user count = %d, want 1", got)
	}
	if err := validator.Del(withEmail.Email); err != nil {
		t.Fatal(err)
	}
	if got := validator.GetCount(); got != 0 {
		t.Fatalf("user count after delete = %d, want 0", got)
	}
}

func TestMemoryValidatorGetAllReturnsIndependentSlice(t *testing.T) {
	validator := new(MemoryValidator)
	user := &protocol.MemoryUser{Email: "copy@example.com", Account: &MemoryAccount{ID: protocol.NewID(uuid.UUID{15: 1})}}
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}
	validator.Warmup()
	users := validator.GetAll()
	if len(users) != 1 || users[0] != user {
		t.Fatalf("users = %+v, want [%p]", users, user)
	}
	users[0] = nil
	if got := validator.GetAll(); len(got) != 1 || got[0] != user {
		t.Fatalf("mutating returned slice changed snapshot: %+v", got)
	}
}

func TestMemoryValidatorNormalizesUnicodeEmail(t *testing.T) {
	validator := new(MemoryValidator)
	user := &protocol.MemoryUser{Email: "ÜSER@example.com", Account: &MemoryAccount{ID: protocol.NewID(uuid.UUID{15: 1})}}
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}
	validator.Warmup()
	if got := validator.GetByEmail("üser@example.com"); got != user {
		t.Fatalf("Unicode email lookup = %p, want %p", got, user)
	}
}
