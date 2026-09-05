package vless

import (
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

func TestMemoryValidatorConcurrentMutationsRemainCoherent(t *testing.T) {
	validator := new(MemoryValidator)
	validator.Warmup()
	user := &protocol.MemoryUser{Email: "shared@example.com", Account: &MemoryAccount{ID: protocol.NewID(uuid.UUID{15: 1})}}
	var workers sync.WaitGroup
	start := make(chan struct{})
	for worker := range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for range 10000 {
				if worker%2 == 0 {
					_ = validator.Add(user)
				} else {
					_ = validator.Del(user.Email)
				}
				_ = validator.GetAll()
			}
		}()
	}
	close(start)
	workers.Wait()
	_ = validator.Del(user.Email)
	if validator.GetCount() != 0 || validator.Get(user.Account.(*MemoryAccount).ID.UUID()) != nil {
		t.Fatal("deleted user remains in validator")
	}
}
