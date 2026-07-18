package encoding

import (
	"context"
	"io"
	"net"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	"google.golang.org/protobuf/proto"
)

// HeaderAddons is the decoded, lock-free view used by the server hot path.
// Addons is a protobuf message and must not be copied after first use.
type HeaderAddons struct {
	Flow string
	Seed []byte
}

func (a HeaderAddons) GetFlow() string { return a.Flow }

type flowAddons interface {
	GetFlow() string
}

func EncodeHeaderAddons(buffer *buf.Buffer, addons *Addons) error {
	switch addons.Flow {
	case vless.XRV:
		bytes, err := proto.Marshal(addons)
		if err != nil {
			return errors.New("failed to marshal addons protobuf value").Base(err)
		}
		if err := buffer.WriteByte(byte(len(bytes))); err != nil {
			return errors.New("failed to write addons protobuf length").Base(err)
		}
		if _, err := buffer.Write(bytes); err != nil {
			return errors.New("failed to write addons protobuf value").Base(err)
		}
	default:
		if err := buffer.WriteByte(0); err != nil {
			return errors.New("failed to write addons protobuf length").Base(err)
		}
	}

	return nil
}

func DecodeHeaderAddons(buffer *buf.Buffer, reader io.Reader) (*Addons, error) {
	addons := new(Addons)
	buffer.Clear()
	if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
		return nil, errors.New("failed to read addons protobuf length").Base(err)
	}

	if length := int32(buffer.Byte(0)); length != 0 {
		buffer.Clear()
		if _, err := buffer.ReadFullFrom(reader, length); err != nil {
			return nil, errors.New("failed to read addons protobuf value").Base(err)
		}

		if err := proto.Unmarshal(buffer.Bytes(), addons); err != nil {
			return nil, errors.New("failed to unmarshal addons protobuf value").Base(err)
		}

		// Verification.
		switch addons.Flow {
		default:
		}
	}

	return addons, nil
}

func decodeHeaderAddonsValue(buffer *buf.Buffer, reader io.Reader) (HeaderAddons, error) {
	var length byte
	if byteReader, ok := reader.(io.ByteReader); ok {
		value, err := byteReader.ReadByte()
		if err != nil {
			return HeaderAddons{}, errors.New("failed to read addons protobuf length").Base(err)
		}
		length = value
	} else {
		buffer.Clear()
		if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
			return HeaderAddons{}, errors.New("failed to read addons protobuf length").Base(err)
		}
		length = buffer.Byte(0)
	}
	if length == 0 {
		return HeaderAddons{}, nil
	}

	buffer.Clear()
	if _, err := buffer.ReadFullFrom(reader, int32(length)); err != nil {
		return HeaderAddons{}, errors.New("failed to read addons protobuf value").Base(err)
	}
	var addons Addons
	if err := proto.Unmarshal(buffer.Bytes(), &addons); err != nil {
		return HeaderAddons{}, errors.New("failed to unmarshal addons protobuf value").Base(err)
	}
	return HeaderAddons{Flow: addons.Flow, Seed: addons.Seed}, nil
}

// EncodeBodyAddons returns a Writer that auto-encrypt content written by caller.
func EncodeBodyAddons(writer buf.Writer, request *protocol.RequestHeader, requestAddons flowAddons, state *proxy.TrafficState, isUplink bool, context context.Context, conn net.Conn, ob *session.Outbound) buf.Writer {
	return EncodeBodyAddonsFlow(writer, request, requestAddons.GetFlow(), state, isUplink, context, conn, ob)
}

// EncodeBodyAddonsFlow avoids boxing the server's lock-free HeaderAddons value.
func EncodeBodyAddonsFlow(writer buf.Writer, request *protocol.RequestHeader, flow string, state *proxy.TrafficState, isUplink bool, context context.Context, conn net.Conn, ob *session.Outbound) buf.Writer {
	return EncodeBody(writer, request, flow == vless.XRV, state, isUplink, context, conn, ob)
}

// EncodeBody uses the caller's already-classified Vision mode.
func EncodeBody(writer buf.Writer, request *protocol.RequestHeader, vision bool, state *proxy.TrafficState, isUplink bool, context context.Context, conn net.Conn, ob *session.Outbound) buf.Writer {
	if request.Command == protocol.RequestCommandUDP {
		return NewMultiLengthPacketWriter(writer)
	}
	if vision {
		return proxy.NewVisionWriter(writer, state, isUplink, context, conn, ob, request.User.Account.(*vless.MemoryAccount).Testseed)
	}
	return writer
}

// DecodeBodyAddons returns a Reader from which caller can fetch decrypted body.
func DecodeBodyAddons(reader io.Reader, request *protocol.RequestHeader, addons flowAddons) buf.Reader {
	_ = addons.GetFlow()
	return DecodeBody(reader, request)
}

// DecodeBodyAddonsFlow avoids boxing the server's lock-free HeaderAddons value.
func DecodeBodyAddonsFlow(reader io.Reader, request *protocol.RequestHeader, flow string) buf.Reader {
	_ = flow
	return DecodeBody(reader, request)
}

// DecodeBody selects framing solely from the request command. VLESS response
// flow does not alter body decoding.
func DecodeBody(reader io.Reader, request *protocol.RequestHeader) buf.Reader {
	if request.Command == protocol.RequestCommandUDP {
		return NewLengthPacketReader(reader)
	}
	return buf.NewReader(reader)
}

func NewMultiLengthPacketWriter(writer buf.Writer) *MultiLengthPacketWriter {
	return &MultiLengthPacketWriter{
		Writer: writer,
	}
}

type MultiLengthPacketWriter struct {
	buf.Writer
}

// NewTrafficStateForFlow creates the shared Vision state only when the flow uses it.
func NewTrafficStateForFlow(userUUID []byte, flow string) *proxy.TrafficState {
	return NewTrafficStateForVision(userUUID, flow == vless.XRV)
}

// NewTrafficStateForVision uses an already-classified flow mode.
func NewTrafficStateForVision(userUUID []byte, vision bool) *proxy.TrafficState {
	if !vision {
		return nil
	}
	return proxy.NewTrafficState(userUUID)
}

func (w *MultiLengthPacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	mb2Write := make(buf.MultiBuffer, 0, len(mb)+1)
	for _, b := range mb {
		length := b.Len()
		if length == 0 || length+2 > buf.Size {
			continue
		}
		eb := buf.New()
		if err := eb.WriteByte(byte(length >> 8)); err != nil {
			eb.Release()
			continue
		}
		if err := eb.WriteByte(byte(length)); err != nil {
			eb.Release()
			continue
		}
		if _, err := eb.Write(b.Bytes()); err != nil {
			eb.Release()
			continue
		}
		mb2Write = append(mb2Write, eb)
	}
	if mb2Write.IsEmpty() {
		return nil
	}
	return w.Writer.WriteMultiBuffer(mb2Write)
}

func NewLengthPacketWriter(writer io.Writer) *LengthPacketWriter {
	return &LengthPacketWriter{
		Writer: writer,
		cache:  make([]byte, 0, 65536),
	}
}

type LengthPacketWriter struct {
	io.Writer
	cache []byte
}

func (w *LengthPacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	length := mb.Len() // none of mb is nil
	// fmt.Println("Write", length)
	if length == 0 {
		return nil
	}
	defer func() {
		w.cache = w.cache[:0]
	}()
	w.cache = append(w.cache, byte(length>>8), byte(length))
	for i, b := range mb {
		w.cache = append(w.cache, b.Bytes()...)
		b.Release()
		mb[i] = nil
	}
	if _, err := w.Write(w.cache); err != nil {
		return errors.New("failed to write a packet").Base(err)
	}
	return nil
}

func NewLengthPacketReader(reader io.Reader) *LengthPacketReader {
	return &LengthPacketReader{
		Reader: reader,
		cache:  make([]byte, 2),
	}
}

type LengthPacketReader struct {
	io.Reader
	cache []byte
}

func (r *LengthPacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if _, err := io.ReadFull(r.Reader, r.cache); err != nil { // maybe EOF
		return nil, errors.New("failed to read packet length").Base(err)
	}
	length := int32(r.cache[0])<<8 | int32(r.cache[1])
	// fmt.Println("Read", length)
	mb := make(buf.MultiBuffer, 0, length/buf.Size+1)
	for length > 0 {
		size := length
		if size > buf.Size {
			size = buf.Size
		}
		length -= size
		b := buf.New()
		if _, err := b.ReadFullFrom(r.Reader, size); err != nil {
			return nil, errors.New("failed to read packet payload").Base(err)
		}
		mb = append(mb, b)
	}
	return mb, nil
}
