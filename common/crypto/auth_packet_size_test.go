package crypto_test

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"
	"testing/iotest"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/protocol"
)

// peerStream returns the authenticator constructor shared by a peer and a
// reader, and the chunks the peer sealed for payloads, one chunk each, then
// the empty chunk that ends the body.
func peerStream(t *testing.T, payloads [][]byte) (func() *crypto.AEADAuthenticator, *bytes.Buffer) {
	t.Helper()
	key := make([]byte, 16)
	common.Must2(rand.Read(key))
	aead := crypto.NewAesGcm(key)
	iv := make([]byte, 12)
	common.Must2(rand.Read(iv))
	authenticator := func() *crypto.AEADAuthenticator {
		return &crypto.AEADAuthenticator{
			AEAD:                    aead,
			NonceGenerator:          crypto.GenerateIncreasingNonce(iv),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		}
	}
	peer := authenticator()
	var stream bytes.Buffer
	for _, payload := range append(payloads, nil) {
		sealed, err := peer.Seal(nil, payload)
		common.Must(err)
		stream.Write(binary.BigEndian.AppendUint16(nil, uint16(len(sealed))))
		stream.Write(sealed)
	}
	return authenticator, &stream
}

// A peer may send a datagram in a chunk above buf.Size, which Xray's writer
// does not, and up to the 65535 bytes the chunk length allows. The reader
// merged such a chunk into the buffer before it and split it over buffers of
// buf.Size bytes, so the outbound sent datagrams the client never sent. It
// must keep every datagram whole, in a buffer of its own.
//
// It runs over a stream that is all buffered, and over one that arrives a byte
// at a time, so that a large chunk is read both with and after others.
func TestAuthenticationReaderKeepsLargeDatagramsWhole(t *testing.T) {
	overhead := crypto.NewAesGcm(make([]byte, 16)).Overhead()
	datagrams := [][]byte{
		bytes.Repeat([]byte{1}, 9000),
		bytes.Repeat([]byte{2}, 100),
		bytes.Repeat([]byte{3}, buf.Size-overhead),   // a chunk of buf.Size bytes
		bytes.Repeat([]byte{4}, buf.Size-overhead+1), // a chunk one byte larger
		bytes.Repeat([]byte{5}, 200),
		bytes.Repeat([]byte{6}, 65535-overhead), // the largest chunk
	}
	for name, arrive := range map[string]func(io.Reader) io.Reader{
		"buffered":         func(r io.Reader) io.Reader { return r },
		"a byte at a time": iotest.OneByteReader,
	} {
		t.Run(name, func(t *testing.T) {
			authenticator, stream := peerStream(t, datagrams)
			reader := crypto.NewAuthenticationReader(authenticator(), crypto.PlainChunkSizeParser{}, arrive(stream), protocol.TransferTypePacket, nil)
			var got [][]byte
			for {
				mb, err := reader.ReadMultiBuffer()
				for _, b := range mb {
					got = append(got, bytes.Clone(b.Bytes()))
				}
				buf.ReleaseMulti(mb)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("after %d datagrams: %v", len(got), err)
				}
			}
			if len(got) != len(datagrams) {
				t.Fatalf("read %d datagrams of %v bytes, want %d of %v", len(got), lengths(got), len(datagrams), lengths(datagrams))
			}
			for i := range datagrams {
				if !bytes.Equal(got[i], datagrams[i]) {
					t.Fatalf("datagram %d holds %d bytes other than the %d sent", i, len(got[i]), len(datagrams[i]))
				}
			}
		})
	}
}

// A stream keeps its bytes in order whatever the chunk sizes: the reader
// merges a chunk above buf.Size into the buffers around it.
func TestAuthenticationReaderStreamKeepsLargeChunksInOrder(t *testing.T) {
	chunks := [][]byte{bytes.Repeat([]byte{1}, 100), bytes.Repeat([]byte{2}, 9000), bytes.Repeat([]byte{3}, 200)}
	authenticator, stream := peerStream(t, chunks)
	reader := crypto.NewAuthenticationReader(authenticator(), crypto.PlainChunkSizeParser{}, stream, protocol.TransferTypeStream, nil)
	var got bytes.Buffer
	for {
		mb, err := reader.ReadMultiBuffer()
		for _, b := range mb {
			got.Write(b.Bytes())
		}
		buf.ReleaseMulti(mb)
		if err == io.EOF {
			break
		}
		common.Must(err)
	}
	if !bytes.Equal(got.Bytes(), bytes.Join(chunks, nil)) {
		t.Fatalf("read %d bytes other than the %d sent", got.Len(), len(bytes.Join(chunks, nil)))
	}
}

func lengths(datagrams [][]byte) []int {
	sizes := make([]int, len(datagrams))
	for i, datagram := range datagrams {
		sizes[i] = len(datagram)
	}
	return sizes
}
