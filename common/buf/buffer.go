package buf

import (
	"io"
	stdnet "net"
	"net/netip"
	"sync"
	"unsafe"

	"github.com/xtls/xray-core/common/bytespool"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

const (
	// Size of a regular buffer.
	Size = 8192
)

var ErrBufferFull = errors.New("buffer is full")

var (
	fixedBufferPool   sync.Pool
	managedBufferPool sync.Pool
)

// managedBuffer pools the 8K storage together with the inline packet metadata.
// It deliberately does NOT embed the Buffer header: a header living inside the
// pooled object is handed back out by the next New(), so a stale holder that
// releases twice frees a buffer its new owner is still using, and the slab
// returns to the pool while live. Stale and live holders would be one pointer,
// which no flag or generation counter inside Release() can tell apart. A header
// on the heap keeps the identities distinct, so the b.v == nil guard in
// Release() makes a second release harmless again.
type managedBuffer struct {
	udp       net.Destination
	udpIPv4   bufferIPv4Address
	udpDomain bufferDomainAddress
	udpIsIPv4 bool
	single    [1]*Buffer
	storage   [Size]byte
}

func acquireFixedBuffer() []byte {
	storage, _ := fixedBufferPool.Get().(*[Size]byte)
	if storage == nil {
		storage = new([Size]byte)
	}
	return storage[:]
}

// ownership represents the data owner of the buffer.
type ownership uint8

const (
	managed ownership = iota
	unmanaged
	bytespools
)

// Buffer is a recyclable allocation of a byte array. Buffer.Release() recycles
// the buffer into an internal buffer pool, in order to recreate a buffer more
// quickly.
type Buffer struct {
	v         []byte
	start     int32
	end       int32
	ownership ownership
	slab      bool
	UDP       *net.Destination
}

// New creates a Buffer with 0 length and 8K capacity, managed.
func New() *Buffer {
	slab, _ := managedBufferPool.Get().(*managedBuffer)
	if slab == nil {
		slab = new(managedBuffer)
	}
	return &Buffer{v: slab.storage[:], slab: true}
}

// NewExisted creates a standard size Buffer with an existed bytearray, managed.
func NewExisted(b []byte) *Buffer {
	if cap(b) < Size {
		panic("Invalid buffer")
	}

	oLen := len(b)
	if oLen < Size {
		b = b[:Size]
	}

	return &Buffer{
		v:   b,
		end: int32(oLen),
	}
}

// FromBytes creates a Buffer with an existed bytearray, unmanaged.
func FromBytes(b []byte) *Buffer {
	return &Buffer{
		v:         b,
		end:       int32(len(b)),
		ownership: unmanaged,
	}
}

// StackNew creates a new Buffer object on stack, managed.
// This method is for buffers that is released in the same function.
func StackNew() Buffer {
	buf := acquireFixedBuffer()

	return Buffer{
		v: buf,
	}
}

// NewWithSize creates a Buffer with 0 length and capacity with at least the given size, bytespool's.
func NewWithSize(size int32) *Buffer {
	return &Buffer{
		v:         bytespool.Alloc(size),
		ownership: bytespools,
	}
}

// Release recycles the buffer into an internal buffer pool.
func (b *Buffer) Release() {
	if b == nil || b.v == nil || b.ownership == unmanaged {
		return
	}

	p := b.v

	switch b.ownership {
	case managed:
		if b.slab {
			slab := managedBufferFromStorage(p)
			*b = Buffer{}
			slab.udp = net.Destination{}
			slab.udpIPv4 = bufferIPv4Address{}
			slab.udpDomain = bufferDomainAddress{}
			slab.udpIsIPv4 = false
			slab.single[0] = nil
			managedBufferPool.Put(slab)
			return
		}
		if cap(p) == Size {
			fixedBufferPool.Put((*[Size]byte)(p[:Size]))
		}
	case bytespools:
		bytespool.Free(p)
	}
	*b = Buffer{}
}

func managedBufferFromStorage(storage []byte) *managedBuffer {
	return (*managedBuffer)(unsafe.Add(unsafe.Pointer(&storage[0]), -int(unsafe.Offsetof(managedBuffer{}.storage))))
}

// SetUDPDestination stores packet metadata inline for managed buffers, avoiding
// a per-packet Destination allocation. Unmanaged buffers retain value ownership
// through a regular heap-backed pointer.
func (b *Buffer) SetUDPDestination(destination net.Destination) {
	if b.slab {
		b.SetManagedUDPDestination(destination)
		return
	}
	b.UDP = &destination
}

// SetManagedUDPDestination stores packet metadata without a heap fallback.
// The receiver must have been created by New.
func (b *Buffer) SetManagedUDPDestination(destination net.Destination) {
	if !b.slab {
		panic("SetManagedUDPDestination called on unmanaged buffer")
	}
	slab := managedBufferFromStorage(b.v)
	slab.udp = destination
	slab.udpDomain.domain = ""
	slab.udpIsIPv4 = false
	b.UDP = &slab.udp
}

type bufferIPv4Address [4]byte

func (a *bufferIPv4Address) IP() stdnet.IP           { return stdnet.IP(a[:]) }
func (*bufferIPv4Address) Domain() string            { panic("Calling Domain() on an IPv4Address.") }
func (*bufferIPv4Address) Family() net.AddressFamily { return net.AddressFamilyIPv4 }
func (a *bufferIPv4Address) String() string          { return a.IP().String() }
func (a *bufferIPv4Address) NetIPAddr() netip.Addr   { return netip.AddrFrom4([4]byte(*a)) }
func (a *bufferIPv4Address) RawIPv4() [4]byte        { return [4]byte(*a) }

type bufferDomainAddress struct {
	domain string
}

func (*bufferDomainAddress) IP() stdnet.IP             { panic("Calling IP() on a DomainAddress.") }
func (a *bufferDomainAddress) Domain() string          { return a.domain }
func (*bufferDomainAddress) Family() net.AddressFamily { return net.AddressFamilyDomain }
func (a *bufferDomainAddress) String() string          { return a.domain }

// SetManagedUDPIPv4 stores an IPv4 packet destination entirely in the managed
// slab, including the Address interface target.
func (b *Buffer) SetManagedUDPIPv4(ip [4]byte, port net.Port) {
	if !b.slab {
		panic("SetManagedUDPIPv4 called on unmanaged buffer")
	}
	slab := managedBufferFromStorage(b.v)
	slab.udpIPv4 = bufferIPv4Address(ip)
	slab.udpDomain.domain = ""
	slab.udp = net.UDPDestination(&slab.udpIPv4, port)
	slab.udpIsIPv4 = true
	b.UDP = &slab.udp
}

// SetManagedUDPDomain stores domain packet metadata in the managed slab,
// avoiding an interface box allocation. The domain string must own its bytes.
func (b *Buffer) SetManagedUDPDomain(domain string, port net.Port) {
	if !b.slab {
		panic("SetManagedUDPDomain called on unmanaged buffer")
	}
	slab := managedBufferFromStorage(b.v)
	slab.udpDomain.domain = domain
	slab.udp = net.UDPDestination(&slab.udpDomain, port)
	slab.udpIsIPv4 = false
	b.UDP = &slab.udp
}

// ManagedUDPIPv4 returns inline IPv4 packet metadata without going through
// the Address interface. The result is available only after SetManagedUDPIPv4.
func (b *Buffer) ManagedUDPIPv4() ([4]byte, net.Port, bool) {
	if !b.slab {
		return [4]byte{}, 0, false
	}
	slab := managedBufferFromStorage(b.v)
	if !slab.udpIsIPv4 {
		return [4]byte{}, 0, false
	}
	return [4]byte(slab.udpIPv4), slab.udp.Port, true
}

// ManagedUDPDomain returns inline domain metadata without going through the
// generic Address interface. It succeeds only after SetManagedUDPDomain.
func (b *Buffer) ManagedUDPDomain() (string, net.Port, bool) {
	if !b.slab || b.UDP == nil {
		return "", 0, false
	}
	slab := managedBufferFromStorage(b.v)
	address, ok := slab.udp.Address.(*bufferDomainAddress)
	if !ok || address != &slab.udpDomain {
		return "", 0, false
	}
	return slab.udpDomain.domain, slab.udp.Port, true
}

// SingleMultiBuffer returns an owned one-element view backed by the managed
// slab. The view is valid until the buffer is released.
func (b *Buffer) SingleMultiBuffer() MultiBuffer {
	if b.slab {
		slab := managedBufferFromStorage(b.v)
		slab.single[0] = b
		return slab.single[:]
	}
	return MultiBuffer{b}
}

// Clear clears the content of the buffer, results an empty buffer with
// Len() = 0.
func (b *Buffer) Clear() {
	b.start = 0
	b.end = 0
}

// Byte returns the bytes at index.
func (b *Buffer) Byte(index int32) byte {
	return b.v[b.start+index]
}

// SetByte sets the byte value at index.
func (b *Buffer) SetByte(index int32, value byte) {
	b.v[b.start+index] = value
}

// Bytes returns the content bytes of this Buffer.
func (b *Buffer) Bytes() []byte {
	return b.v[b.start:b.end]
}

// Extend increases the buffer size by n bytes, and returns the extended part.
// It panics if result size is larger than size of this buffer.
func (b *Buffer) Extend(n int32) []byte {
	end := b.end + n
	if end > int32(len(b.v)) {
		panic("extending out of bound")
	}
	ext := b.v[b.end:end]
	b.end = end
	clear(ext)
	return ext
}

// BytesRange returns a slice of this buffer with given from and to boundary.
func (b *Buffer) BytesRange(from, to int32) []byte {
	if from < 0 {
		from += b.Len()
	}
	if to < 0 {
		to += b.Len()
	}
	return b.v[b.start+from : b.start+to]
}

// BytesFrom returns a slice of this Buffer starting from the given position.
func (b *Buffer) BytesFrom(from int32) []byte {
	if from < 0 {
		from += b.Len()
	}
	return b.v[b.start+from : b.end]
}

// BytesTo returns a slice of this Buffer from start to the given position.
func (b *Buffer) BytesTo(to int32) []byte {
	if to < 0 {
		to += b.Len()
	}
	if to < 0 {
		to = 0
	}
	return b.v[b.start : b.start+to]
}

// Check makes sure that 0 <= b.start <= b.end.
func (b *Buffer) Check() {
	if b.start < 0 {
		b.start = 0
	}
	if b.end < 0 {
		b.end = 0
	}
	if b.start > b.end {
		b.start = b.end
	}
}

// Resize cuts the buffer at the given position.
func (b *Buffer) Resize(from, to int32) {
	oldEnd := b.end
	if from < 0 {
		from += b.Len()
	}
	if to < 0 {
		to += b.Len()
	}
	if to < from {
		panic("Invalid slice")
	}
	b.end = b.start + to
	b.start += from
	b.Check()
	if b.end > oldEnd {
		clear(b.v[oldEnd:b.end])
	}
}

// Advance cuts the buffer at the given position.
func (b *Buffer) Advance(from int32) {
	if from < 0 {
		from += b.Len()
	}
	b.start += from
	b.Check()
}

// Len returns the length of the buffer content.
func (b *Buffer) Len() int32 {
	if b == nil {
		return 0
	}
	return b.end - b.start
}

// Cap returns the capacity of the buffer content.
func (b *Buffer) Cap() int32 {
	if b == nil {
		return 0
	}
	return int32(len(b.v))
}

// Available returns the available capacity of the buffer content.
func (b *Buffer) Available() int32 {
	if b == nil {
		return 0
	}
	return int32(len(b.v)) - b.end
}

// IsEmpty returns true if the buffer is empty.
func (b *Buffer) IsEmpty() bool {
	return b.Len() == 0
}

// IsFull returns true if the buffer has no more room to grow.
func (b *Buffer) IsFull() bool {
	return b != nil && b.end == int32(len(b.v))
}

// Write implements Write method in io.Writer.
func (b *Buffer) Write(data []byte) (int, error) {
	nBytes := copy(b.v[b.end:], data)
	b.end += int32(nBytes)
	if nBytes < len(data) {
		return nBytes, ErrBufferFull
	}
	return nBytes, nil
}

// WriteByte writes a single byte into the buffer.
func (b *Buffer) WriteByte(v byte) error {
	if b.IsFull() {
		return ErrBufferFull
	}
	b.v[b.end] = v
	b.end++
	return nil
}

// WriteString implements io.StringWriter.
func (b *Buffer) WriteString(s string) (int, error) {
	return b.Write([]byte(s))
}

// ReadByte implements io.ByteReader
func (b *Buffer) ReadByte() (byte, error) {
	if b.start == b.end {
		return 0, io.EOF
	}

	nb := b.v[b.start]
	b.start++
	return nb, nil
}

// ReadBytes implements bufio.Reader.ReadBytes
func (b *Buffer) ReadBytes(length int32) ([]byte, error) {
	if b.end-b.start < length {
		return nil, io.EOF
	}

	nb := b.v[b.start : b.start+length]
	b.start += length
	return nb, nil
}

// Read implements io.Reader.Read().
func (b *Buffer) Read(data []byte) (int, error) {
	if b.Len() == 0 {
		return 0, io.EOF
	}
	nBytes := copy(data, b.v[b.start:b.end])
	if int32(nBytes) == b.Len() {
		b.Clear()
	} else {
		b.start += int32(nBytes)
	}
	return nBytes, nil
}

// ReadFrom implements io.ReaderFrom.
func (b *Buffer) ReadFrom(reader io.Reader) (int64, error) {
	n, err := reader.Read(b.v[b.end:])
	b.end += int32(n)
	return int64(n), err
}

// ReadFullFrom reads exact size of bytes from given reader, or until error occurs.
func (b *Buffer) ReadFullFrom(reader io.Reader, size int32) (int64, error) {
	end := b.end + size
	if end > int32(len(b.v)) {
		v := end
		return 0, errors.New("out of bound: ", v)
	}
	n, err := io.ReadFull(reader, b.v[b.end:end])
	b.end += int32(n)
	return int64(n), err
}

// String returns the string form of this Buffer.
func (b *Buffer) String() string {
	return string(b.Bytes())
}
