package account

import (
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

var (
	validatorUserSink  *protocol.MemoryUser
	validatorCountSink int64
	validatorBoolSink  bool
	validatorUsersSink []*protocol.MemoryUser
)

func TestParseAuthUUIDPreservesAcceptedFormats(t *testing.T) {
	canonical := "00112233-4455-6677-8899-aabbccddeeff"
	want := uuid.MustParse(canonical)
	tests := []struct {
		name  string
		auth  string
		valid bool
	}{
		{name: "canonical", auth: canonical, valid: true},
		{name: "compact", auth: "00112233445566778899aabbccddeeff", valid: true},
		{name: "braces", auth: "{" + canonical + "}", valid: true},
		{name: "URN", auth: "URN:UUID:" + canonical, valid: true},
		{name: "bad canonical hex", auth: "00112233-4455-6677-8899-aabbccddegff"},
		{name: "bad canonical separators", auth: "001122334455-6677-8899-aabbccddeeff"},
		{name: "opaque token", auth: "opaque-auth-token"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := parseAuthUUID(test.auth)
			if ok != test.valid {
				t.Fatalf("valid=%v, want %v", ok, test.valid)
			}
			if ok && got != want {
				t.Fatalf("uuid=%s, want %s", got, want)
			}
		})
	}
}

func benchmarkValidator(b *testing.B, count int) (*Validator, string) {
	b.Helper()
	validator := NewValidator()
	target := ""
	for index := range count {
		auth := fmt.Sprintf("00000000-0000-0000-0000-%012x", index+1)
		user := &protocol.MemoryUser{
			Email:   fmt.Sprintf("user-%d@example.com", index),
			Account: &MemoryAccount{Auth: auth},
		}
		if err := validator.Add(user); err != nil {
			b.Fatal(err)
		}
		target = auth
	}
	return validator, target
}

func BenchmarkValidatorGetUUID(b *testing.B) {
	validator, target := benchmarkValidator(b, 1024)
	b.ReportAllocs()
	for b.Loop() {
		validatorUserSink = validator.Get(target)
	}
}

func BenchmarkValidatorGetToken(b *testing.B) {
	validator := NewValidator()
	user := &protocol.MemoryUser{Email: "token@example.com", Account: &MemoryAccount{Auth: "opaque-auth-token"}}
	if err := validator.Add(user); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		validatorUserSink = validator.Get("opaque-auth-token")
	}
}

func BenchmarkValidatorGetByEmail(b *testing.B) {
	validator, _ := benchmarkValidator(b, 1024)
	b.ReportAllocs()
	for b.Loop() {
		validatorUserSink = validator.GetByEmail("user-1023@example.com")
	}
}

func BenchmarkValidatorGetCount(b *testing.B) {
	validator, _ := benchmarkValidator(b, 1024)
	b.ReportAllocs()
	for b.Loop() {
		validatorCountSink = validator.GetCount()
	}
}

func BenchmarkValidatorNotEmpty(b *testing.B) {
	validator, _ := benchmarkValidator(b, 1024)
	b.ReportAllocs()
	for b.Loop() {
		validatorBoolSink = validator.NotEmpty()
	}
}

func BenchmarkValidatorGetAll(b *testing.B) {
	validator, _ := benchmarkValidator(b, 1024)
	b.ReportAllocs()
	for b.Loop() {
		validatorUsersSink = validator.GetAll()
	}
}

func TestValidatorCountTracksAddReplaceAndDelete(t *testing.T) {
	validator := NewValidator()
	user := &protocol.MemoryUser{Email: "user@example.com", Account: &MemoryAccount{Auth: "token"}}
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}
	if validator.GetCount() != 1 || !validator.NotEmpty() {
		t.Fatalf("after replacement count=%d notEmpty=%v", validator.GetCount(), validator.NotEmpty())
	}
	if err := validator.DelByEmail(user.Email); err != nil {
		t.Fatal(err)
	}
	if validator.GetCount() != 0 || validator.NotEmpty() {
		t.Fatalf("after delete count=%d notEmpty=%v", validator.GetCount(), validator.NotEmpty())
	}
}

func TestValidatorEmailIndexTracksRenameAndDelete(t *testing.T) {
	validator := NewValidator()
	first := &protocol.MemoryUser{Email: "first@example.com", Account: &MemoryAccount{Auth: "token"}}
	if err := validator.Add(first); err != nil {
		t.Fatal(err)
	}
	replacement := &protocol.MemoryUser{Email: "second@example.com", Account: &MemoryAccount{Auth: "token"}}
	if err := validator.Add(replacement); err != nil {
		t.Fatal(err)
	}
	if validator.GetByEmail(first.Email) != nil || validator.GetByEmail(replacement.Email) != replacement {
		t.Fatal("email index did not track auth replacement")
	}
	if err := validator.DelByEmail(replacement.Email); err != nil {
		t.Fatal(err)
	}
	if validator.GetByEmail(replacement.Email) != nil {
		t.Fatal("email index retained deleted user")
	}
}

func TestValidatorSnapshotTracksDynamicUsers(t *testing.T) {
	validator := NewValidator()
	first := &protocol.MemoryUser{Email: "first@example.com", Account: &MemoryAccount{Auth: "opaque-first"}}
	if err := validator.Add(first); err != nil {
		t.Fatal(err)
	}
	validator.Warmup()
	secondAuth := "00000000-0000-0000-0000-000000000002"
	second := &protocol.MemoryUser{Email: "second@example.com", Account: &MemoryAccount{Auth: secondAuth}}
	if err := validator.Add(second); err != nil {
		t.Fatal(err)
	}
	if validator.Get("opaque-first") != first || validator.Get(secondAuth) != second {
		t.Fatal("snapshot did not publish dynamic add")
	}
	if err := validator.DelByEmail(second.Email); err != nil {
		t.Fatal(err)
	}
	if validator.Get(secondAuth) != nil {
		t.Fatal("snapshot retained deleted UUID user")
	}
}

func TestValidatorExactUUIDAndRouteVariant(t *testing.T) {
	const auth = "00112233-4455-6677-8899-aabbccddeeff"
	parsed := uuid.MustParse(auth)
	user := &protocol.MemoryUser{
		Email:   "uuid@example.com",
		Account: &MemoryAccount{Auth: auth, VR: net.PortFromBytes(parsed[6:8])},
	}
	validator := NewValidator()
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}
	validator.Warmup()
	if got := validator.Get(auth); got != user {
		t.Fatal("exact UUID did not return the configured user")
	}

	const variant = "00112233-4455-1234-8899-aabbccddeeff"
	got := validator.Get(variant)
	if got == nil || got == user {
		t.Fatal("route variant did not create a per-auth user")
	}
	account := got.Account.(*MemoryAccount)
	if account.Auth != variant || account.VR != 0x1234 {
		t.Fatalf("route account auth=%q VR=%d", account.Auth, account.VR)
	}
}

func TestValidatorSnapshotConcurrentReaders(t *testing.T) {
	validator := NewValidator()
	user := &protocol.MemoryUser{Email: "concurrent@example.com", Account: &MemoryAccount{Auth: "opaque-concurrent"}}
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}
	validator.Warmup()
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
					_ = validator.Get(user.Account.(*MemoryAccount).Auth)
				}
			}
		}()
	}
	for range 100 {
		if err := validator.Add(user); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	readers.Wait()
}
