package quic

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

// referenceStream is a byte-by-byte model of receivedBytes and the CRYPTO
// stream it guards.
type referenceStream struct {
	received [cryptoStreamCap]bool
	stream   [cryptoStreamCap]byte
}

// fill applies the contract of receivedBytes.fill to the model.
func (m *referenceStream) fill(data []byte, from int32) bool {
	for i, b := range data {
		at := from + int32(i)
		if !m.received[at] {
			m.received[at] = true
			m.stream[at] = b
		} else if m.stream[at] != b {
			return false
		}
	}
	return true
}

// prefix applies the contract of receivedBytes.prefix to the model.
func (m *referenceStream) prefix(known, end int32) int32 {
	for known < end && m.received[known] {
		known++
	}
	return known
}

// receivedBytes must behave exactly like the byte-by-byte model, whatever
// the frames: aligned or not, overlapping, repeated, conflicting, empty, or
// at the end of the stream cap.
func TestReceivedBytesMatchesReferenceModel(t *testing.T) {
	r := rand.New(rand.NewPCG(0x5eed, 0xb175))
	for round := range 3000 {
		var streamLen int32
		switch round % 3 {
		case 0:
			streamLen = 1 + r.Int32N(200)
		case 1:
			streamLen = 1 + r.Int32N(2000)
		default:
			streamLen = cryptoStreamCap - r.Int32N(200)
		}
		truth := make([]byte, streamLen)
		for i := range truth {
			truth[i] = byte(r.IntN(256))
		}
		var received receivedBytes
		stream := make([]byte, cryptoStreamCap)
		model := &referenceStream{}
		for frame := range 1 + r.IntN(12) {
			from := r.Int32N(streamLen)
			if r.IntN(4) == 0 {
				from &^= 7
			}
			length := r.Int32N(streamLen - from + 1)
			if r.IntN(8) == 0 {
				length = 0
			}
			data := bytes.Clone(truth[from : from+length])
			if length > 0 && r.IntN(10) == 0 {
				data[r.Int32N(length)] ^= 1 << r.IntN(8)
			}
			got := received.fill(stream[from:from+length], data, from)
			if want := model.fill(data, from); got != want {
				t.Fatalf("round %d frame %d: fill(offset %d, length %d) = %v, want %v", round, frame, from, length, got, want)
			}
			if !got {
				break
			}
			for at := range streamLen {
				if gotBit := received[at/8]&(1<<(at%8)) != 0; gotBit != model.received[at] {
					t.Fatalf("round %d frame %d: byte %d received = %v, want %v", round, frame, at, gotBit, model.received[at])
				}
				if model.received[at] && stream[at] != model.stream[at] {
					t.Fatalf("round %d frame %d: byte %d = %#x, want %#x", round, frame, at, stream[at], model.stream[at])
				}
			}
			for range 4 {
				end := r.Int32N(streamLen + 1)
				known := r.Int32N(end + 1)
				if got, want := received.prefix(known, end), model.prefix(known, end); got != want {
					t.Fatalf("round %d frame %d: prefix(%d, %d) = %d, want %d", round, frame, known, end, got, want)
				}
			}
		}
	}
}

// BenchmarkReceivedBytes measures what SniffQUIC spends on receivedBytes for
// a first flight: the bitmap starts empty, the frames are filled in, and the
// prefix received without a gap is found.
func BenchmarkReceivedBytes(b *testing.B) {
	const helloLen = 1600
	data := make([]byte, helloLen)
	r := rand.New(rand.NewPCG(1, 2))
	for i := range data {
		data[i] = byte(r.IntN(256))
	}
	type frame struct{ from, to int32 }
	// Chrome's ClientHello fragments: unaligned, shuffled, one of them sent
	// twice.
	shuffled := []frame{{913, 1290}, {0, 287}, {1290, 1600}, {287, 640}, {640, 913}, {287, 640}}
	// sized cuts the ClientHello into frames of size bytes starting at
	// offset, every step bytes, and then fills the gaps.
	sized := func(offset, size, step int32) []frame {
		var frames []frame
		for at := offset; at < helloLen; at += step {
			frames = append(frames, frame{at, min(at+size, helloLen)})
		}
		if step > size || offset > 0 {
			frames = append(frames, frame{0, helloLen})
		}
		return frames
	}
	for _, bench := range []struct {
		name   string
		frames []frame
	}{
		{"one frame", []frame{{0, helloLen}}},
		{"shuffled fragments", shuffled},
		{"one-byte frames", sized(0, 1, 1)},
		{"one-byte frames with gaps", sized(0, 1, 2)},
		{"eight-byte frames", sized(3, 8, 8)},
		{"32-byte frames", sized(5, 32, 32)},
	} {
		b.Run(bench.name, func(b *testing.B) {
			stream := make([]byte, helloLen)
			for b.Loop() {
				var received receivedBytes
				for _, f := range bench.frames {
					if !received.fill(stream[f.from:f.to], data[f.from:f.to], f.from) {
						b.Fatal("conflict")
					}
				}
				if received.prefix(0, helloLen) != helloLen {
					b.Fatal("gap")
				}
			}
		})
	}
}

// runEnd applies the contract of receivedBytes.runEnd to the model.
func (m *referenceStream) runEnd(at, end int32, received bool) int32 {
	for at < end && m.received[at] == received {
		at++
	}
	return at
}

// mark applies the contract of receivedBytes.mark to the model.
func (m *referenceStream) mark(from, to int32) {
	for at := from; at < to; at++ {
		m.received[at] = true
	}
}

// setReceived sets the bit of the byte at offset at without going through
// receivedBytes' own methods.
func setReceived(r *receivedBytes, at int32) {
	r[at/8] |= 1 << (at % 8)
}

// isReceived reads the bit of the byte at offset at.
func isReceived(r *receivedBytes, at int32) bool {
	return r[at/8]&(1<<(at%8)) != 0
}

// receivedBytesBoundaries are offsets at and around every boundary the
// bitmap has: bytes of 8 bits, words of 64 bits, and the stream cap.
var receivedBytesBoundaries = []int32{
	0, 1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 62, 63, 64, 65, 66, 127, 128, 129,
	191, 192, 193, 255, 256, 257, 4095, 4096, 4097,
	cryptoStreamCap - 129, cryptoStreamCap - 128, cryptoStreamCap - 127,
	cryptoStreamCap - 65, cryptoStreamCap - 64, cryptoStreamCap - 63,
	cryptoStreamCap - 9, cryptoStreamCap - 8, cryptoStreamCap - 7,
	cryptoStreamCap - 2, cryptoStreamCap - 1, cryptoStreamCap,
}

// receivedBytesBackgrounds are the bytes that have arrived before an
// operation: none, all, and patterns whose runs start and end on and off the
// byte and word boundaries.
func receivedBytesBackgrounds() []struct {
	name     string
	received func(at int32) bool
} {
	dense := rand.New(rand.NewPCG(7, 8))
	denseBits := make([]bool, cryptoStreamCap)
	sparseBits := make([]bool, cryptoStreamCap)
	runs := make([]bool, cryptoStreamCap)
	for at := range denseBits {
		denseBits[at] = dense.IntN(10) != 0
		sparseBits[at] = dense.IntN(10) == 0
	}
	for at, on := 0, false; at < cryptoStreamCap; on = !on {
		n := 1 + dense.IntN(150)
		for i := at; i < min(at+n, cryptoStreamCap); i++ {
			runs[i] = on
		}
		at += n
	}
	return []struct {
		name     string
		received func(at int32) bool
	}{
		{"none", func(int32) bool { return false }},
		{"all", func(int32) bool { return true }},
		{"every other byte", func(at int32) bool { return at%2 == 0 }},
		{"every eighth byte", func(at int32) bool { return at%8 == 7 }},
		{"first half of each word", func(at int32) bool { return at%64 < 32 }},
		{"all but word edges", func(at int32) bool { return at%64 != 0 && at%64 != 63 }},
		{"all but the boundaries", func(at int32) bool {
			for _, b := range receivedBytesBoundaries {
				if at == b || at == b-1 {
					return false
				}
			}
			return true
		}},
		{"random dense", func(at int32) bool { return denseBits[at] }},
		{"random sparse", func(at int32) bool { return sparseBits[at] }},
		{"random runs", func(at int32) bool { return runs[at] }},
	}
}

// truthByte is the stream byte at offset at in the boundary tests.
func truthByte(at int32) byte {
	return byte(at*7 + 3)
}

// runEnd, mark, prefix and fill must agree with the byte-by-byte model for
// every pair of offsets at and around a byte, word or cap boundary, over
// backgrounds whose runs start and end on and off those boundaries. A byte
// that has not arrived holds junk, so reading or comparing it shows.
func TestReceivedBytesBoundaries(t *testing.T) {
	stream := make([]byte, cryptoStreamCap)
	for _, background := range receivedBytesBackgrounds() {
		var base receivedBytes
		baseModel := &referenceStream{}
		for at := range int32(cryptoStreamCap) {
			if background.received(at) {
				setReceived(&base, at)
				baseModel.received[at] = true
				baseModel.stream[at] = truthByte(at)
			}
		}
		for _, from := range receivedBytesBoundaries {
			for _, to := range receivedBytesBoundaries {
				if from > to {
					continue
				}
				for _, received := range []bool{true, false} {
					if got, want := base.runEnd(from, to, received), baseModel.runEnd(from, to, received); got != want {
						t.Fatalf("%s: runEnd(%d, %d, %v) = %d, want %d", background.name, from, to, received, got, want)
					}
				}
				if got, want := base.prefix(from, to), baseModel.prefix(from, to); got != want {
					t.Fatalf("%s: prefix(%d, %d) = %d, want %d", background.name, from, to, got, want)
				}

				marked := base
				marked.mark(from, to)
				for at := range int32(cryptoStreamCap) {
					want := baseModel.received[at] || at >= from && at < to
					if isReceived(&marked, at) != want {
						t.Fatalf("%s: after mark(%d, %d) byte %d received = %v, want %v", background.name, from, to, at, !want, want)
					}
				}

				// fill with the stream's own bytes, then with one byte changed at
				// each end of the frame.
				variants := [][]int32{nil}
				if to > from {
					variants = append(variants, []int32{from}, []int32{to - 1})
				}
				for _, changed := range variants {
					filled := base
					model := *baseModel
					for at := from; at < to; at++ {
						if background.received(at) {
							stream[at] = truthByte(at)
						} else {
							stream[at] = 0xEE
						}
					}
					data := make([]byte, to-from)
					for i := range data {
						data[i] = truthByte(from + int32(i))
					}
					for _, at := range changed {
						data[at-from] ^= 0x5A
					}
					got := filled.fill(stream[from:to], data, from)
					if want := model.fill(data, from); got != want {
						t.Fatalf("%s: fill(%d, %d) changing %v = %v, want %v", background.name, from, to, changed, got, want)
					}
					if !got {
						continue
					}
					for at := from; at < to; at++ {
						if !isReceived(&filled, at) || stream[at] != model.stream[at] {
							t.Fatalf("%s: after fill(%d, %d) byte %d = (%v, %#x), want (true, %#x)", background.name, from, to, at, isReceived(&filled, at), stream[at], model.stream[at])
						}
					}
					if filled != func() receivedBytes {
						want := base
						for at := from; at < to; at++ {
							setReceived(&want, at)
						}
						return want
					}() {
						t.Fatalf("%s: fill(%d, %d) changed bits outside its frame", background.name, from, to)
					}
				}
			}
		}
	}
}

// FuzzReceivedBytes applies fuzzed operations to receivedBytes and the model
// in a 512-byte window at the start or at the end of the stream cap, where
// frames overlap densely, and compares every result.
func FuzzReceivedBytes(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0, 255, 1, 0, 10, 0, 20, 2, 0, 5, 0, 0})
	f.Add([]byte{1, 0, 1, 255, 0, 64, 4, 0, 63, 0, 2, 0, 0, 62, 0, 70})
	f.Fuzz(func(t *testing.T, ops []byte) {
		if len(ops) == 0 {
			return
		}
		const window = 512
		base := int32(0)
		if ops[0]&1 == 1 {
			base = cryptoStreamCap - window
		}
		ops = ops[1:]
		var r receivedBytes
		var model referenceStream
		stream := make([]byte, cryptoStreamCap)
		for len(ops) >= 5 {
			kind := ops[0]
			from := base + int32(ops[1])<<8%window + int32(ops[2])%window
			from = base + (from-base)%window
			length := (int32(ops[3])<<8 | int32(ops[4])) % (base + window - from + 1)
			ops = ops[5:]
			to := from + length
			switch kind % 4 {
			case 0, 1:
				data := make([]byte, length)
				for i := range data {
					data[i] = truthByte(from + int32(i))
				}
				if kind&0x10 != 0 && length > 0 {
					data[int32(kind>>5)%length] ^= 1
				}
				got := r.fill(stream[from:to], data, from)
				if want := model.fill(data, from); got != want {
					t.Fatalf("fill(%d, %d) = %v, want %v", from, to, got, want)
				}
				if !got {
					return
				}
			case 2:
				r.mark(from, to)
				model.mark(from, to)
			case 3:
				received := kind&0x10 != 0
				if got, want := r.runEnd(from, to, received), model.runEnd(from, to, received); got != want {
					t.Fatalf("runEnd(%d, %d, %v) = %d, want %d", from, to, received, got, want)
				}
				if got, want := r.prefix(from, to), model.prefix(from, to); got != want {
					t.Fatalf("prefix(%d, %d) = %d, want %d", from, to, got, want)
				}
			}
			for at := base; at < base+window; at++ {
				if isReceived(&r, at) != model.received[at] {
					t.Fatalf("byte %d received = %v, want %v", at, isReceived(&r, at), model.received[at])
				}
				if model.received[at] && kind%4 < 2 && stream[at] != model.stream[at] {
					t.Fatalf("byte %d = %#x, want %#x", at, stream[at], model.stream[at])
				}
			}
		}
	})
}
