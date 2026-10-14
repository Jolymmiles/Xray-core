package mux_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/transport"
)

// A peer may frame a packet above buf.Size, which Xray's writer does not, up
// to the 65535 bytes the length allows. The reader refused it, which ended the
// mux connection with every session on it; it must read the packet whole and
// leave the stream at the next frame.
func TestPacketReaderKeepsLargePacketsWhole(t *testing.T) {
	payload := bytes.Repeat([]byte{7}, 9000)
	var stream bytes.Buffer
	stream.Write(binary.BigEndian.AppendUint16(nil, uint16(len(payload))))
	stream.Write(payload)
	stream.WriteString("next frame")

	destination := net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 53)
	reader := mux.NewPacketReader(&stream, &destination)
	mb, err := reader.ReadMultiBuffer()
	if err != nil || len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), payload) {
		t.Fatalf("ReadMultiBuffer() = %d buffers of %d bytes, %v; want the packet of %d bytes", len(mb), mb.Len(), err, len(payload))
	}
	if mb[0].UDP == nil || *mb[0].UDP != destination {
		t.Fatalf("the packet is addressed to %v, want %v", mb[0].UDP, destination)
	}
	buf.ReleaseMulti(mb)
	if stream.String() != "next frame" {
		t.Fatalf("the reader left %d bytes, want the next frame", stream.Len())
	}
	if _, err := reader.ReadMultiBuffer(); err != io.EOF {
		t.Fatalf("after the packet: %v, want io.EOF", err)
	}
}

// The server worker must hand a large packet on whole, and serve the frames
// after it.
func TestServerWorkerKeepsLargePacketsWhole(t *testing.T) {
	type delivery struct {
		destination string
		sizes       []int
	}
	received := make(chan delivery, 4)
	dispatcher := TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			uplink, downlink := newLinkPair()
			go func() {
				for {
					mb, err := uplink.Reader.ReadMultiBuffer()
					if !mb.IsEmpty() {
						sizes := make([]int, len(mb))
						for i, b := range mb {
							sizes[i] = int(b.Len())
						}
						received <- delivery{dest.NetAddr(), sizes}
					}
					buf.ReleaseMulti(mb)
					if err != nil {
						return
					}
				}
			}()
			return downlink, nil
		},
	}
	serverUplink, serverDownlink := newLinkPair()
	worker, err := mux.NewServerWorker(context.Background(), &dispatcher, serverUplink)
	common.Must(err)
	t.Cleanup(func() { common.Close(serverDownlink.Writer) })

	// Xray's writer drops a packet above buf.Size, so the peer's frame is
	// built here.
	first := net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 53)
	frame := buf.New()
	common.Must((mux.FrameMetadata{
		SessionID: 1, SessionStatus: mux.SessionStatusNew, Target: first, Option: mux.OptionData,
	}).WriteTo(frame))
	common.Must2(frame.Write(binary.BigEndian.AppendUint16(nil, 9000)))
	large := buf.NewWithSize(9000)
	large.Extend(9000)
	common.Must(serverDownlink.Writer.WriteMultiBuffer(buf.MultiBuffer{frame, large}))
	second := net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 2}), 53)
	common.Must(mux.NewWriter(2, second, serverDownlink.Writer, protocol.TransferTypePacket, [8]byte{}, nil).
		WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("ping"))}))

	want := map[string][]int{first.NetAddr(): {9000}, second.NetAddr(): {4}}
	for range want {
		select {
		case got := <-received:
			if sizes, ok := want[got.destination]; !ok || len(got.sizes) != 1 || got.sizes[0] != sizes[0] {
				t.Fatalf("%s received buffers of %v bytes, want %v", got.destination, got.sizes, sizes)
			}
		case <-worker.WaitClosed():
			t.Fatal("the worker ended the mux connection on the large packet")
		case <-time.After(10 * time.Second):
			t.Fatal("a session was not served")
		}
	}
}

// An older Xray mux reader ends the connection on a packet above buf.Size, so
// the writer drops one rather than frame it, as the XUDP writer drops its
// own.
func TestWriterDropsPacketsOlderReadersRefuse(t *testing.T) {
	var frames buf.MultiBufferContainer
	destination := net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 53)
	writer := mux.NewWriter(1, destination, &frames, protocol.TransferTypePacket, [8]byte{}, nil)
	large := buf.NewWithSize(buf.Size + 1)
	large.Extend(buf.Size + 1)
	fits := buf.NewWithSize(buf.Size)
	fits.Extend(buf.Size)
	common.Must(writer.WriteMultiBuffer(buf.MultiBuffer{large, fits, buf.FromBytes([]byte("small"))}))

	var sizes []int
	for {
		var meta mux.FrameMetadata
		if err := meta.Unmarshal(&frames, false); err != nil {
			if err != io.EOF {
				t.Fatalf("after %d packets: %v", len(sizes), err)
			}
			break
		}
		if !meta.Option.Has(mux.OptionData) {
			continue
		}
		mb, err := mux.NewPacketReader(&frames, &meta.Target).ReadMultiBuffer()
		if err != nil {
			t.Fatalf("after %d packets, reading a packet: %v", len(sizes), err)
		}
		sizes = append(sizes, int(mb.Len()))
		buf.ReleaseMulti(mb)
	}
	if len(sizes) != 2 || sizes[0] != buf.Size || sizes[1] != len("small") {
		t.Fatalf("framed packets of %v bytes, want %d and %d", sizes, buf.Size, len("small"))
	}
}
