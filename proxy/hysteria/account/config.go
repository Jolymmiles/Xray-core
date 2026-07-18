package account

import (
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func (a *Account) AsAccount() (protocol.Account, error) {
	var VR net.Port
	if id, ok := parseAuthUUID(a.Auth); ok {
		VR = net.PortFromBytes(id[6:8])
	}
	return &MemoryAccount{
		Auth: a.Auth,
		VR:   VR,
	}, nil
}

var uuidHexValues = [256]byte{
	'0': 1, '1': 2, '2': 3, '3': 4, '4': 5, '5': 6, '6': 7, '7': 8,
	'8': 9, '9': 10,
	'a': 11, 'b': 12, 'c': 13, 'd': 14, 'e': 15, 'f': 16,
	'A': 11, 'B': 12, 'C': 13, 'D': 14, 'E': 15, 'F': 16,
}

var canonicalUUIDHexOffsets = [...]uint8{
	0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34,
}

func parseAuthUUID(auth string) (uuid.UUID, bool) {
	if len(auth) != 36 {
		id, err := uuid.Parse(auth)
		return id, err == nil
	}
	var id uuid.UUID
	if auth[8] != '-' || auth[13] != '-' || auth[18] != '-' || auth[23] != '-' {
		return id, false
	}
	for index, offset := range canonicalUUIDHexOffsets {
		high := uuidHexValues[auth[offset]]
		low := uuidHexValues[auth[offset+1]]
		if high == 0 || low == 0 {
			return uuid.UUID{}, false
		}
		id[index] = (high-1)<<4 | (low - 1)
	}
	return id, true
}

type MemoryAccount struct {
	Auth string
	VR   net.Port
}

func (a *MemoryAccount) Equals(other protocol.Account) bool {
	if b, ok := other.(*MemoryAccount); ok {
		return a.Auth == b.Auth
	}
	return false
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{
		Auth: a.Auth,
	}
}

type Validator struct {
	users      sync.Map
	ids        sync.Map
	emails     sync.Map
	mu         sync.Mutex
	count      atomic.Int64
	generation atomic.Uint64
	snapshot   atomic.Pointer[validatorSnapshot]
}

type validatorSnapshot struct {
	generation uint64
	users      map[string]*protocol.MemoryUser
	ids        map[uuid.UUID]*protocol.MemoryUser
}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) Add(user *protocol.MemoryUser) (err error) {
	v.mu.Lock()
	warmed := v.snapshot.Load() != nil
	auth := user.Account.(*MemoryAccount).Auth
	previous, loaded := v.users.Swap(auth, user)
	if !loaded {
		v.count.Add(1)
	} else if previousUser := previous.(*protocol.MemoryUser); previousUser.Email != user.Email {
		v.emails.CompareAndDelete(previousUser.Email, previousUser)
	}
	v.emails.Store(user.Email, user)
	if id, ok := parseAuthUUID(auth); ok {
		id[6] = 0
		id[7] = 0
		v.ids.Store(id, user)
	}
	generation := v.generation.Add(1)
	if warmed {
		v.rebuildSnapshotLocked(generation)
	}
	v.mu.Unlock()
	return
}

func (v *Validator) DelByEmail(email string) (err error) {
	v.mu.Lock()
	warmed := v.snapshot.Load() != nil
	if user := v.GetByEmail(email); user != nil {
		auth := user.Account.(*MemoryAccount).Auth
		if _, loaded := v.users.LoadAndDelete(auth); loaded {
			v.count.Add(-1)
		}
		v.emails.CompareAndDelete(user.Email, user)
		if id, ok := parseAuthUUID(auth); ok {
			id[6] = 0
			id[7] = 0
			v.ids.Delete(id)
		}
		generation := v.generation.Add(1)
		if warmed {
			v.rebuildSnapshotLocked(generation)
		}
	}
	v.mu.Unlock()
	return
}

func (v *Validator) Get(auth string) (user *protocol.MemoryUser) {
	generation := v.generation.Load()
	if snapshot := v.snapshot.Load(); snapshot != nil && snapshot.generation == generation {
		if user = snapshot.users[auth]; user != nil {
			return user
		}
	}
	if id, ok := parseAuthUUID(auth); ok {
		if user = v.GetByID(id); user != nil {
			VR := net.PortFromBytes(id[6:8])
			if user.Account.(*MemoryAccount).VR != VR {
				user = &protocol.MemoryUser{
					Email: user.Email,
					Level: user.Level,
					Account: &MemoryAccount{
						Auth: auth,
						VR:   VR,
					},
				}
			}
		}
		return
	}
	if snapshot := v.snapshot.Load(); snapshot != nil && snapshot.generation == generation {
		return snapshot.users[auth]
	}
	if value, ok := v.users.Load(auth); ok {
		user = value.(*protocol.MemoryUser)
	}
	v.refreshSnapshot(generation)
	return
}

func (v *Validator) GetByID(id uuid.UUID) (user *protocol.MemoryUser) {
	id[6] = 0
	id[7] = 0
	generation := v.generation.Load()
	if snapshot := v.snapshot.Load(); snapshot != nil && snapshot.generation == generation {
		return snapshot.ids[id]
	}
	if value, ok := v.ids.Load(id); ok {
		user = value.(*protocol.MemoryUser)
	}
	v.refreshSnapshot(generation)
	return
}

// Warmup publishes immutable auth lookup maps after bulk configuration load.
func (v *Validator) Warmup() {
	v.refreshSnapshot(v.generation.Load())
}

func (v *Validator) refreshSnapshot(generation uint64) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if snapshot := v.snapshot.Load(); snapshot != nil && snapshot.generation == generation {
		return
	}
	v.rebuildSnapshotLocked(v.generation.Load())
}

func (v *Validator) rebuildSnapshotLocked(generation uint64) {
	count := int(v.count.Load())
	users := make(map[string]*protocol.MemoryUser, count)
	ids := make(map[uuid.UUID]*protocol.MemoryUser, count)
	v.users.Range(func(key, value any) bool {
		users[key.(string)] = value.(*protocol.MemoryUser)
		return true
	})
	v.ids.Range(func(key, value any) bool {
		ids[key.(uuid.UUID)] = value.(*protocol.MemoryUser)
		return true
	})
	v.snapshot.Store(&validatorSnapshot{generation: generation, users: users, ids: ids})
}

func (v *Validator) GetByEmail(email string) (user *protocol.MemoryUser) {
	if value, ok := v.emails.Load(email); ok {
		return value.(*protocol.MemoryUser)
	}
	return nil
}

func (v *Validator) GetAll() []*protocol.MemoryUser {
	users := make([]*protocol.MemoryUser, 0, int(v.count.Load()))
	v.users.Range(func(key, value any) bool {
		users = append(users, value.(*protocol.MemoryUser))
		return true
	})
	return users
}

func (v *Validator) GetCount() (count int64) {
	return v.count.Load()
}

func (v *Validator) NotEmpty() (not_empty bool) {
	return v.count.Load() != 0
}
