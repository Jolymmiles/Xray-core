package mtproxy

import (
	"errors"
	"sync"
	"testing"
)

func TestSecretRegistryAddListDeleteAndCapacity(t *testing.T) {
	registry, err := NewSecretRegistry(2)
	if err != nil {
		t.Fatal(err)
	}
	first := testSecret(1)
	second := testSecret(2)
	third := testSecret(3)

	firstFingerprint, added, err := registry.Add(first)
	if err != nil || !added {
		t.Fatalf("Add(first) = %v, %v, %v", firstFingerprint, added, err)
	}
	duplicateFingerprint, added, err := registry.Add(first)
	if err != nil || added || duplicateFingerprint != firstFingerprint {
		t.Fatalf("duplicate Add = %v, %v, %v", duplicateFingerprint, added, err)
	}
	secondFingerprint, added, err := registry.Add(second)
	if err != nil || !added {
		t.Fatalf("Add(second) = %v, %v, %v", secondFingerprint, added, err)
	}
	if _, _, err := registry.Add(third); !errors.Is(err, ErrSecretCapacity) {
		t.Fatalf("Add(third) error = %v, want ErrSecretCapacity", err)
	}

	listed := registry.List()
	if len(listed) != 2 || listed[0] != secondFingerprint || listed[1] != firstFingerprint {
		t.Fatalf("List() = %v, want newest first", listed)
	}
	if !registry.Delete(firstFingerprint) {
		t.Fatal("Delete(first) = false")
	}
	if registry.Delete(firstFingerprint) {
		t.Fatal("second Delete(first) = true")
	}
	if registry.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", registry.Len())
	}
}

func TestSecretRegistryConcurrentMutationAndSnapshots(t *testing.T) {
	registry, err := NewSecretRegistry(64)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				secret := testSecret(byte(worker*17 + i))
				fingerprint, _, err := registry.Add(secret)
				if err != nil && !errors.Is(err, ErrSecretCapacity) {
					t.Errorf("Add() error = %v", err)
					return
				}
				snapshot := registry.candidates()
				for _, candidate := range snapshot {
					if candidate.runtime == nil {
						t.Error("snapshot contains nil runtime")
						return
					}
				}
				registry.Delete(fingerprint)
			}
		}()
	}
	wg.Wait()
	if registry.Len() > 64 {
		t.Fatalf("Len() = %d, exceeds capacity", registry.Len())
	}
}
