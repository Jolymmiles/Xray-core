package encoding_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/protocol"
	. "github.com/xtls/xray-core/proxy/vmess/encoding"
)

// With global padding, the length of each chunk's padding and the mask of its
// size come from one SHAKE stream that both peers read a chunk at a time. The
// packet writer took the padding length of a datagram too large for a chunk
// and then dropped the datagram, so the peer read every later chunk with the
// wrong mask and padding, and the session was lost. The writer must drop such
// a datagram without taking from the stream, and send the next.
func TestAuthenticationWriterDropsWithoutDesyncingPadding(t *testing.T) {
	key := make([]byte, 16)
	common.Must2(rand.Read(key))
	iv := make([]byte, 16)
	common.Must2(rand.Read(iv))
	aead := crypto.NewAesGcm(key)
	auth := func() *crypto.AEADAuthenticator {
		return &crypto.AEADAuthenticator{
			AEAD:                    aead,
			NonceGenerator:          GenerateChunkNonce(iv, uint32(aead.NonceSize())),
			AdditionalDataGenerator: crypto.GenerateEmptyBytes(),
		}
	}
	var stream bytes.Buffer
	writerParser := NewShakeSizeParser(iv)
	writer := crypto.NewAuthenticationWriter(auth(), writerParser, &stream, protocol.TransferTypePacket, writerParser)
	readerParser := NewShakeSizeParser(iv)
	reader := crypto.NewAuthenticationReader(auth(), readerParser, &stream, protocol.TransferTypePacket, readerParser)

	// A datagram of 8190 bytes fits no chunk with its tag; one of 8100 fits
	// with any padding.
	sent := [][]byte{[]byte("ping"), bytes.Repeat([]byte{2}, 8190), bytes.Repeat([]byte{3}, 8100), []byte("pong")}
	for i := 0; i < 32; i++ {
		mb := make(buf.MultiBuffer, len(sent))
		for j, datagram := range sent {
			mb[j] = buf.New()
			mb[j].Write(datagram)
		}
		if err := writer.WriteMultiBuffer(mb); err != nil {
			t.Fatal(err)
		}
		var got buf.MultiBuffer
		for len(got) < 3 {
			mb, err := reader.ReadMultiBuffer()
			if err != nil {
				t.Fatalf("round %d: reading after %d datagrams: %v", i, len(got), err)
			}
			got = append(got, mb...)
		}
		for j, want := range [][]byte{sent[0], sent[2], sent[3]} {
			if !bytes.Equal(got[j].Bytes(), want) {
				t.Fatalf("round %d: datagram %d holds %d bytes, want %d", i, j, got[j].Len(), len(want))
			}
		}
		if len(got) != 3 {
			t.Fatalf("round %d: read %d datagrams, want 3", i, len(got))
		}
		buf.ReleaseMulti(got)
	}
}
