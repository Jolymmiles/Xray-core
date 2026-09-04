package vless

import (
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

type validatorUserSnapshot struct {
	generation uint64
	users      map[string]*protocol.MemoryUser
	singleID   [16]byte
	singleUser *protocol.MemoryUser
}

type validatorEmailSnapshot struct {
	generation uint64
	users      []*protocol.MemoryUser
	byEmail    map[string]*protocol.MemoryUser
}

type Validator interface {
	Get(id uuid.UUID) *protocol.MemoryUser
	Add(u *protocol.MemoryUser) error
	Del(email string) error
	GetByEmail(email string) *protocol.MemoryUser
	GetAll() []*protocol.MemoryUser
	GetCount() int64
}

func ProcessUUID(id [16]byte) [16]byte {
	id[6] = 0
	id[7] = 0
	return id
}

func normalizeEmail(email string) string {
	for i := 0; i < len(email); i++ {
		c := email[i]
		if c >= 'A' && c <= 'Z' || c >= 0x80 {
			return strings.ToLower(email)
		}
	}
	return email
}

// MemoryValidator stores valid VLESS users.
type MemoryValidator struct {
	// Map publication and its counters must remain one mutation against deletion.
	mutationMu sync.Mutex
	// Considering email's usage here, map + sync.Mutex/RWMutex may have better performance.
	email               sync.Map
	emailCount          atomic.Int64
	emailGeneration     atomic.Uint64
	emailSnapshot       atomic.Pointer[validatorEmailSnapshot]
	emailSnapshotUpdate sync.Mutex
	users               sync.Map
	userCount           atomic.Int64
	userGeneration      atomic.Uint64
	userSnapshot        atomic.Pointer[validatorUserSnapshot]
	userSnapshotUpdate  sync.Mutex
}

// Add a VLESS user, Email must be empty or unique.
func (v *MemoryValidator) Add(u *protocol.MemoryUser) error {
	v.mutationMu.Lock()
	defer v.mutationMu.Unlock()
	if u.Email != "" {
		warmed := v.emailSnapshot.Load() != nil
		_, loaded := v.email.LoadOrStore(normalizeEmail(u.Email), u)
		if loaded {
			return errors.New("User ", u.Email, " already exists.")
		}
		v.emailCount.Add(1)
		generation := v.emailGeneration.Add(1)
		if warmed {
			v.refreshEmailSnapshot(generation)
		}
	}
	warmed := v.userSnapshot.Load() != nil
	key := ProcessUUID(u.Account.(*MemoryAccount).ID.UUID())
	if _, loaded := v.users.Swap(key, u); !loaded {
		v.userCount.Add(1)
	}
	generation := v.userGeneration.Add(1)
	if warmed {
		v.refreshUserSnapshot(generation)
	}
	return nil
}

// Del a VLESS user with a non-empty Email.
func (v *MemoryValidator) Del(e string) error {
	v.mutationMu.Lock()
	defer v.mutationMu.Unlock()
	if e == "" {
		return errors.New("Email must not be empty.")
	}
	le := normalizeEmail(e)
	u, loaded := v.email.LoadAndDelete(le)
	if !loaded {
		return errors.New("User ", e, " not found.")
	}
	v.emailCount.Add(-1)
	emailGeneration := v.emailGeneration.Add(1)
	if v.emailSnapshot.Load() != nil {
		v.refreshEmailSnapshot(emailGeneration)
	}
	warmed := v.userSnapshot.Load() != nil
	if _, loaded := v.users.LoadAndDelete(ProcessUUID(u.(*protocol.MemoryUser).Account.(*MemoryAccount).ID.UUID())); loaded {
		v.userCount.Add(-1)
	}
	generation := v.userGeneration.Add(1)
	if warmed {
		v.refreshUserSnapshot(generation)
	}
	return nil
}

// Get a VLESS user with UUID, nil if user doesn't exist.
func (v *MemoryValidator) Get(id uuid.UUID) *protocol.MemoryUser {
	key := ProcessUUID(id)
	generation := v.userGeneration.Load()
	if snapshot := v.userSnapshot.Load(); snapshot != nil && snapshot.generation == generation {
		if snapshot.users != nil {
			return snapshot.users[unsafe.String(&key[0], len(key))]
		}
		if snapshot.singleUser != nil {
			if key == snapshot.singleID {
				return snapshot.singleUser
			}
		}
		return nil
	}

	u, _ := v.users.Load(key)
	v.refreshUserSnapshot(generation)
	if u != nil {
		return u.(*protocol.MemoryUser)
	}
	return nil
}

func (v *MemoryValidator) refreshUserSnapshot(generation uint64) {
	if !v.userSnapshotUpdate.TryLock() {
		return
	}
	defer v.userSnapshotUpdate.Unlock()
	if snapshot := v.userSnapshot.Load(); snapshot != nil && snapshot.generation == generation {
		return
	}
	generation = v.userGeneration.Load()
	count := int(v.userCount.Load())
	var users map[string]*protocol.MemoryUser
	if count > 1 {
		users = make(map[string]*protocol.MemoryUser, count)
	}
	var singleID [16]byte
	var singleUser *protocol.MemoryUser
	v.users.Range(func(key, value any) bool {
		id := key.([16]byte)
		user := value.(*protocol.MemoryUser)
		if count == 1 {
			singleID = id
			singleUser = user
		} else if users != nil {
			users[string(id[:])] = user
		}
		return true
	})
	if generation == v.userGeneration.Load() {
		v.userSnapshot.Store(&validatorUserSnapshot{
			generation: generation,
			users:      users,
			singleID:   singleID,
			singleUser: singleUser,
		})
	}
}

// Warmup builds the immutable lookup snapshot after bulk configuration loads,
// keeping the first client handshake off the snapshot construction path.
func (v *MemoryValidator) Warmup() {
	v.refreshUserSnapshot(v.userGeneration.Load())
	v.refreshEmailSnapshot(v.emailGeneration.Load())
}

// Get a VLESS user with email, nil if user doesn't exist.
func (v *MemoryValidator) GetByEmail(email string) *protocol.MemoryUser {
	email = normalizeEmail(email)
	generation := v.emailGeneration.Load()
	if snapshot := v.emailSnapshot.Load(); snapshot != nil && snapshot.generation == generation {
		return snapshot.byEmail[email]
	}
	u, _ := v.email.Load(email)
	if u != nil {
		return u.(*protocol.MemoryUser)
	}
	return nil
}

// Get all users
func (v *MemoryValidator) GetAll() []*protocol.MemoryUser {
	generation := v.emailGeneration.Load()
	snapshot := v.emailSnapshot.Load()
	if snapshot == nil || snapshot.generation != generation {
		v.refreshEmailSnapshot(generation)
		snapshot = v.emailSnapshot.Load()
	}
	if snapshot != nil && snapshot.generation == v.emailGeneration.Load() {
		users := make([]*protocol.MemoryUser, len(snapshot.users))
		copy(users, snapshot.users)
		return users
	}
	users := make([]*protocol.MemoryUser, 0, int(v.emailCount.Load()))
	v.email.Range(func(_, value any) bool {
		users = append(users, value.(*protocol.MemoryUser))
		return true
	})
	return users
}

func (v *MemoryValidator) refreshEmailSnapshot(generation uint64) {
	if !v.emailSnapshotUpdate.TryLock() {
		return
	}
	defer v.emailSnapshotUpdate.Unlock()
	if snapshot := v.emailSnapshot.Load(); snapshot != nil && snapshot.generation == generation {
		return
	}
	generation = v.emailGeneration.Load()
	count := int(v.emailCount.Load())
	users := make([]*protocol.MemoryUser, 0, count)
	byEmail := make(map[string]*protocol.MemoryUser, count)
	v.email.Range(func(key, value any) bool {
		user := value.(*protocol.MemoryUser)
		users = append(users, user)
		byEmail[key.(string)] = user
		return true
	})
	if generation == v.emailGeneration.Load() {
		v.emailSnapshot.Store(&validatorEmailSnapshot{generation: generation, users: users, byEmail: byEmail})
	}
}

// Get users count
func (v *MemoryValidator) GetCount() int64 {
	return v.emailCount.Load()
}
