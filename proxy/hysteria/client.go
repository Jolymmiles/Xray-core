package hysteria

import (
	"bytes"
	"context"
	"encoding/binary"
	go_errors "errors"
	"io"
	"math/rand"
	"sync"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type Client struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
}

func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	v := core.MustFromContext(ctx)
	p := v.GetFeature(policy.ManagerType()).(policy.Manager)

	streamSettings := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig)
	if _, ok := streamSettings.ProtocolSettings.(*hysteria.Config); !ok {
		return nil, errors.New("not hysteria transport")
	}
	if config.Server == nil {
		return nil, errors.New(`no target server found`)
	}
	server, err := protocol.NewServerSpecFromPB(config.Server)
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err)
	}

	return &Client{
		server:        server,
		policyManager: p,
	}, nil
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "hysteria"
	ob.CanSpliceCopy = 3
	target := ob.Target

	conn, err := dialer.Dial(hysteria.ContextWithDatagram(ctx, target.Network == net.Network_UDP), c.server.Destination)
	if err != nil {
		return errors.New("failed to find an available destination").AtWarning().Base(err)
	}
	defer conn.Close()
	errors.LogInfo(ctx, "tunneling request to ", target, " via ", target.Network, ":", c.server.Destination.NetAddr())

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	sessionPolicy := c.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, sessionPolicy.Timeouts.ConnectionIdle)

	if newCtx != nil {
		ctx = newCtx
	}

	if target.Network == net.Network_TCP {
		requestDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
			bufferedWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
			err := WriteTCPRequest(bufferedWriter, target.NetAddr())
			if err != nil {
				return errors.New("failed to write request").Base(err)
			}
			if err := bufferedWriter.SetBuffered(false); err != nil {
				return err
			}
			return buf.Copy(link.Reader, bufferedWriter, buf.UpdateActivity(timer))
		}

		responseDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
			ok, msg, err := ReadTCPResponse(conn)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New(msg)
			}
			return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
		}

		responseDoneAndCloseWriter := task.OnSuccessClose(responseDone, link.Writer)
		if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
			return errors.New("connection ends").Base(err)
		}

		return nil
	}

	if target.Network == net.Network_UDP {
		iConn := stat.TryUnwrapStatsConn(conn)
		_, ok := iConn.(*hysteria.InterConn)
		if !ok {
			return errors.New("udp requires hysteria udp transport")
		}

		requestDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

			writer := &UDPWriter{
				writer: conn,
				addr:   target.NetAddr(),
			}

			if err := buf.Copy(link.Reader, writer, buf.UpdateActivity(timer)); err != nil {
				return errors.New("failed to transport all UDP request").Base(err)
			}

			return nil
		}

		responseDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

			reader := &UDPReader{reader: conn}

			if err := buf.Copy(reader, link.Writer, buf.UpdateActivity(timer)); err != nil {
				return errors.New("failed to transport all UDP response").Base(err)
			}

			return nil
		}

		responseDoneAndCloseWriter := task.OnSuccessClose(responseDone, link.Writer)
		if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
			return errors.New("connection ends").Base(err)
		}

		return nil
	}

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}

type UDPWriter struct {
	writer              io.Writer
	addr                string
	defaultHeaderLength int
	managedDomain       string
	managedDomainPort   net.Port
	managedHeaderLength int
	managedIPv4         [4]byte
	managedIPv4Port     net.Port
	managedIPv4Header   int
	buf                 [buf.Size]byte
}

var udpWriterPool sync.Pool

func newPooledUDPWriter(writer io.Writer, address string) *UDPWriter {
	pooled, _ := udpWriterPool.Get().(*UDPWriter)
	if pooled == nil {
		pooled = new(UDPWriter)
	}
	pooled.writer = writer
	pooled.addr = address
	pooled.defaultHeaderLength = 0
	pooled.managedDomain = ""
	pooled.managedDomainPort = 0
	pooled.managedHeaderLength = 0
	pooled.managedIPv4 = [4]byte{}
	pooled.managedIPv4Port = 0
	pooled.managedIPv4Header = 0
	return pooled
}

func releasePooledUDPWriter(writer *UDPWriter) {
	if writer == nil {
		return
	}
	writer.writer = nil
	writer.addr = ""
	writer.defaultHeaderLength = 0
	writer.managedDomain = ""
	writer.managedDomainPort = 0
	writer.managedHeaderLength = 0
	writer.managedIPv4 = [4]byte{}
	writer.managedIPv4Port = 0
	writer.managedIPv4Header = 0
	udpWriterPool.Put(writer)
}

func (w *UDPWriter) SendMessage(msg *UDPMessage) error {
	return w.sendMessage(msg, nil)
}

func (w *UDPWriter) sendMessage(msg *UDPMessage, address []byte) error {
	w.defaultHeaderLength = 0
	w.managedHeaderLength = 0
	w.managedIPv4Header = 0
	var msgN int
	if address == nil {
		msgN = msg.Serialize(w.buf[:])
	} else {
		msgN = msg.serializeAddress(w.buf[:], address)
	}
	if msgN < 0 {
		return nil
	}
	_, err := w.writer.Write(w.buf[:msgN])
	return err
}

func (w *UDPWriter) sendDefaultPayload(data []byte) error {
	w.managedHeaderLength = 0
	w.managedIPv4Header = 0
	headerLength := w.defaultHeaderLength
	if headerLength == 0 {
		addressLength := len(w.addr)
		addressLengthSize := int(quicvarint.Len(uint64(addressLength)))
		headerLength = 8 + addressLengthSize + addressLength
		if headerLength > len(w.buf) {
			return nil
		}
		w.buf[0], w.buf[1], w.buf[2], w.buf[3] = 0, 0, 0, 0
		w.buf[4], w.buf[5], w.buf[6], w.buf[7] = 0, 0, 0, 1
		varintPut(w.buf[8:], uint64(addressLength))
		copy(w.buf[8+addressLengthSize:headerLength], w.addr)
		w.defaultHeaderLength = headerLength
	}
	totalLength := headerLength + len(data)
	if totalLength > len(w.buf) {
		return nil
	}
	copy(w.buf[headerLength:totalLength], data)
	_, err := w.writer.Write(w.buf[:totalLength])
	return err
}

func (w *UDPWriter) sendManagedDomainPayload(data []byte, domain string, port net.Port) error {
	w.defaultHeaderLength = 0
	w.managedIPv4Header = 0
	headerLength := w.managedHeaderLength
	if headerLength == 0 || domain != w.managedDomain || port != w.managedDomainPort {
		frame := w.buf[:9]
		frame = net.UDPDestination(net.DomainAddress(domain), port).AppendNetAddrTo(frame)
		addressLength := len(frame) - 9
		addressLengthSize := int(quicvarint.Len(uint64(addressLength)))
		headerLength = 8 + addressLengthSize + addressLength
		if headerLength > len(w.buf) {
			return nil
		}
		if addressLengthSize > 1 {
			copy(w.buf[8+addressLengthSize:], w.buf[9:9+addressLength])
		}
		w.buf[0], w.buf[1], w.buf[2], w.buf[3] = 0, 0, 0, 0
		w.buf[4], w.buf[5], w.buf[6], w.buf[7] = 0, 0, 0, 1
		varintPut(w.buf[8:], uint64(addressLength))
		w.managedDomain = domain
		w.managedDomainPort = port
		w.managedHeaderLength = headerLength
	}
	totalLength := headerLength + len(data)
	if totalLength > len(w.buf) {
		return nil
	}
	copy(w.buf[headerLength:totalLength], data)
	_, err := w.writer.Write(w.buf[:totalLength])
	return err
}

func (w *UDPWriter) sendDestinationMessage(msg *UDPMessage, destination net.Destination) error {
	w.defaultHeaderLength = 0
	w.managedHeaderLength = 0
	w.managedIPv4Header = 0
	frame := w.buf[:9]
	frame = destination.AppendNetAddrTo(frame)
	return w.sendAddressFrame(msg, frame)
}

func (w *UDPWriter) sendIPv4Message(msg *UDPMessage, ip [4]byte, port net.Port) error {
	w.defaultHeaderLength = 0
	w.managedHeaderLength = 0
	headerLength := w.managedIPv4Header
	if headerLength == 0 || ip != w.managedIPv4 || port != w.managedIPv4Port {
		frame := net.AppendIPv4Port(w.buf[:9], ip, port)
		headerLength = len(frame)
		w.buf[8] = byte(headerLength - 9)
		w.managedIPv4 = ip
		w.managedIPv4Port = port
		w.managedIPv4Header = headerLength
	}
	totalLength := headerLength + len(msg.Data)
	if totalLength > len(w.buf) {
		return nil
	}
	binary.BigEndian.PutUint16(w.buf[4:], msg.PacketID)
	w.buf[6] = msg.FragID
	w.buf[7] = msg.FragCount
	copy(w.buf[headerLength:], msg.Data)
	_, err := w.writer.Write(w.buf[:totalLength])
	return err
}

func (w *UDPWriter) sendAddressFrame(msg *UDPMessage, frame []byte) error {
	if &frame[0] != &w.buf[0] {
		return w.sendMessage(msg, frame[9:])
	}
	addressLength := len(frame) - 9
	addressLengthSize := int(quicvarint.Len(uint64(addressLength)))
	totalLength := 8 + addressLengthSize + addressLength + len(msg.Data)
	if totalLength > len(w.buf) {
		return nil
	}
	if addressLengthSize > 1 {
		copy(w.buf[8+addressLengthSize:], w.buf[9:9+addressLength])
	}
	binary.BigEndian.PutUint16(w.buf[4:], msg.PacketID)
	w.buf[6] = msg.FragID
	w.buf[7] = msg.FragCount
	varintPut(w.buf[8:], uint64(addressLength))
	dataOffset := 8 + addressLengthSize + addressLength
	copy(w.buf[dataOffset:], msg.Data)
	_, err := w.writer.Write(w.buf[:totalLength])
	return err
}

func (w *UDPWriter) sendFragments(message *UDPMessage, maxSize int) error {
	w.defaultHeaderLength = 0
	w.managedHeaderLength = 0
	w.managedIPv4Header = 0
	address := []byte(message.Addr)
	addressLengthSize := int(quicvarint.Len(uint64(len(address))))
	headerLength := 8 + addressLengthSize + len(address)
	maxPayloadSize := maxSize - headerLength
	if maxPayloadSize <= 0 {
		return nil
	}
	fragmentCountValue := (len(message.Data) + maxPayloadSize - 1) / maxPayloadSize
	if fragmentCountValue > 255 {
		return errors.New("too many UDP fragments")
	}
	fragmentCount := uint8(fragmentCountValue)
	w.buf[0], w.buf[1], w.buf[2], w.buf[3] = 0, 0, 0, 0
	binary.BigEndian.PutUint16(w.buf[4:], message.PacketID)
	w.buf[7] = fragmentCount
	varintPut(w.buf[8:], uint64(len(address)))
	copy(w.buf[8+addressLengthSize:headerLength], address)
	for fragmentID, offset := uint8(0), 0; offset < len(message.Data); fragmentID++ {
		end := offset + maxPayloadSize
		if end > len(message.Data) {
			end = len(message.Data)
		}
		w.buf[6] = fragmentID
		copy(w.buf[headerLength:], message.Data[offset:end])
		if _, err := w.writer.Write(w.buf[:headerLength+end-offset]); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

func wrappedDatagramTooLargeError(err error) *quic.DatagramTooLargeError {
	var target *quic.DatagramTooLargeError
	if go_errors.As(err, &target) {
		return target
	}
	return nil
}

func newUDPPacketID() uint16 {
	return uint16(uint64(rand.Uint32())*0xFFFF>>32) + 1
}

func (w *UDPWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for i, b := range mb {
		addr := w.addr

		msg := &UDPMessage{
			SessionID: 0,
			PacketID:  0,
			FragID:    0,
			FragCount: 1,
			Addr:      addr,
			Data:      b.Bytes(),
		}

		var err error
		if b.UDP == nil {
			err = w.sendDefaultPayload(msg.Data)
		} else if ip, port, ok := b.ManagedUDPIPv4(); ok {
			err = w.sendIPv4Message(msg, ip, port)
		} else if domain, port, ok := b.ManagedUDPDomain(); ok {
			err = w.sendManagedDomainPayload(msg.Data, domain, port)
		} else {
			err = w.sendDestinationMessage(msg, *b.UDP)
		}
		if err != nil {
			errTooLarge, tooLarge := err.(*quic.DatagramTooLargeError)
			if !tooLarge {
				errTooLarge = wrappedDatagramTooLargeError(err)
				tooLarge = errTooLarge != nil
			}
			if tooLarge {
				if b.UDP != nil {
					msg.Addr = b.UDP.NetAddr()
				}
				msg.PacketID = newUDPPacketID()
				if err := w.sendFragments(msg, int(errTooLarge.MaxDatagramPayloadSize)); err != nil {
					buf.ReleaseMulti(mb[i:])
					return err
				}
			} else {
				buf.ReleaseMulti(mb[i:])
				return err
			}
		}

		b.Release()
	}

	return nil
}

type UDPReader struct {
	reader         io.Reader
	df             Defragger
	firstBuf       *buf.Buffer
	lastDomain     string
	lastDomainPort net.Port
	lastAddress    string
	serverWriter   UDPWriter
	link           transport.Link
	buf            [hysteria.MaxDatagramFrameSize]byte
	message        UDPMessage
}

var udpReaderPool sync.Pool

func newPooledUDPReader(reader io.Reader) *UDPReader {
	pooled, _ := udpReaderPool.Get().(*UDPReader)
	if pooled == nil {
		pooled = new(UDPReader)
	}
	pooled.reader = reader
	return pooled
}

func releasePooledUDPReader(reader *UDPReader) {
	if reader == nil {
		return
	}
	if reader.firstBuf != nil {
		reader.firstBuf.Release()
	}
	reader.reader = nil
	reader.firstBuf = nil
	reader.lastDomain = ""
	reader.lastDomainPort = 0
	reader.lastAddress = ""
	reader.serverWriter.writer = nil
	reader.serverWriter.addr = ""
	reader.serverWriter.defaultHeaderLength = 0
	reader.serverWriter.managedDomain = ""
	reader.serverWriter.managedDomainPort = 0
	reader.serverWriter.managedHeaderLength = 0
	reader.serverWriter.managedIPv4 = [4]byte{}
	reader.serverWriter.managedIPv4Port = 0
	reader.serverWriter.managedIPv4Header = 0
	reader.link = transport.Link{}
	reader.message = UDPMessage{}
	reader.df.reset()
	reader.df = Defragger{}
	udpReaderPool.Put(reader)
}

func (r *UDPReader) serverPacketDestination(destination udpPacketDestination) net.Destination {
	return destination.Destination()
}

func (r *UDPReader) serverPacketAddress(destination udpPacketDestination) string {
	if destination.isDomain && destination.domain == r.lastDomain && destination.port == r.lastDomainPort {
		return r.lastAddress
	}
	return r.serverPacketDestination(destination).NetAddr()
}

func (r *UDPReader) ReadFrom(p []byte) (n int, addr *net.Destination, err error) {
	n, destination, err := r.readFromDestination(p)
	if err != nil {
		return 0, nil, err
	}
	return n, &destination, nil
}

func (r *UDPReader) readFromDestination(p []byte) (n int, destination net.Destination, err error) {
	n, _, packetDestination, err := r.readFromPacket(p)
	if err != nil {
		return 0, net.Destination{}, err
	}
	return n, r.serverPacketDestination(packetDestination), nil
}

type udpPacketDestination struct {
	destination net.Destination
	ipv4        [4]byte
	domain      string
	port        net.Port
	isIPv4      bool
	isDomain    bool
	managed     bool
}

func (d udpPacketDestination) Destination() net.Destination {
	if d.isIPv4 {
		return net.UDPDestination(net.IPv4Address(d.ipv4), d.port)
	}
	if d.isDomain {
		return net.UDPDestination(net.DomainAddress(d.domain), d.port)
	}
	return d.destination
}

func (d udpPacketDestination) SetBufferDestination(buffer *buf.Buffer) {
	if d.managed {
		return
	}
	if d.isIPv4 {
		buffer.SetManagedUDPIPv4(d.ipv4, d.port)
		return
	}
	if d.isDomain {
		buffer.SetManagedUDPDomain(d.domain, d.port)
		return
	}
	buffer.SetManagedUDPDestination(d.destination)
}

func (r *UDPReader) readFromPacket(p []byte) (n int, data []byte, packetDestination udpPacketDestination, err error) {
	for {
		n, err := r.reader.Read(r.buf[:])
		if err != nil {
			return 0, nil, udpPacketDestination{}, err
		}

		address, err := parseUDPMessageFields(r.buf[:n], &r.message)
		if err != nil {
			continue
		}
		msg := &r.message
		var destination udpPacketDestination
		assembledInOutput := false
		if msg.FragCount > 1 {
			fragment := r.message
			if !r.df.storeClonedFragment(&fragment) {
				continue
			}
			destination, err = r.parseFragmentDestination(address)
			if err != nil {
				r.df.reset()
				continue
			}
			if p != nil && len(p) >= r.df.size {
				msg = r.df.assemble(&fragment, p[:r.df.size])
				assembledInOutput = true
			} else if p != nil {
				r.df.reset()
				continue
			} else {
				msg = r.df.assemble(&fragment, make([]byte, r.df.size))
			}
		} else {
			if ip, port, ok := parseIPv4UDPAddress(address); ok {
				destination.ipv4 = ip
				destination.port = port
				destination.isIPv4 = true
			} else {
				destination.destination, err = parseUDPDestination(string(address))
			}
		}
		if err != nil {
			continue
		}

		if p != nil {
			if assembledInOutput {
				return len(msg.Data), nil, destination, nil
			}
			if len(p) < len(msg.Data) {
				continue
			}
			return copy(p, msg.Data), nil, destination, nil
		}
		return len(msg.Data), msg.Data, destination, nil
	}
}

func parseKnownDomainUDPAddress(address []byte) ([]byte, net.Port, bool) {
	if len(address) == 0 || address[0] == '[' {
		return nil, 0, false
	}
	if address[len(address)-1] == ':' {
		colon := len(address) - 1
		if isKnownDomainPrefix(address, colon) {
			return address[:colon], 0, true
		}
	}
	if len(address) >= 5 {
		colon := len(address) - 4
		if address[colon] == ':' {
			hundreds, tens, ones := address[colon+1]-'0', address[colon+2]-'0', address[colon+3]-'0'
			if hundreds <= 9 && tens <= 9 && ones <= 9 && isKnownDomainPrefix(address, colon) {
				return address[:colon], net.Port(hundreds)*100 + net.Port(tens)*10 + net.Port(ones), true
			}
		}
	}
	if len(address) >= 4 {
		colon := len(address) - 3
		if address[colon] == ':' {
			tens, ones := address[colon+1]-'0', address[colon+2]-'0'
			if tens <= 9 && ones <= 9 && isKnownDomainPrefix(address, colon) {
				return address[:colon], net.Port(tens)*10 + net.Port(ones), true
			}
		}
	}
	if len(address) >= 6 {
		colon := len(address) - 5
		if address[colon] == ':' {
			thousands, hundreds := address[colon+1]-'0', address[colon+2]-'0'
			tens, ones := address[colon+3]-'0', address[colon+4]-'0'
			if thousands <= 9 && hundreds <= 9 && tens <= 9 && ones <= 9 && isKnownDomainPrefix(address, colon) {
				return address[:colon], net.Port(thousands)*1000 + net.Port(hundreds)*100 + net.Port(tens)*10 + net.Port(ones), true
			}
		}
	}
	if len(address) >= 7 {
		colon := len(address) - 6
		if address[colon] == ':' {
			tenThousands, thousands := address[colon+1]-'0', address[colon+2]-'0'
			hundreds, tens, ones := address[colon+3]-'0', address[colon+4]-'0', address[colon+5]-'0'
			value := uint32(tenThousands)*10000 + uint32(thousands)*1000 + uint32(hundreds)*100 + uint32(tens)*10 + uint32(ones)
			if tenThousands <= 9 && thousands <= 9 && hundreds <= 9 && tens <= 9 && ones <= 9 && value <= 65535 && isKnownDomainPrefix(address, colon) {
				return address[:colon], net.Port(value), true
			}
		}
	}
	if len(address) >= 3 {
		colon := len(address) - 2
		if address[colon] == ':' {
			digit := address[colon+1] - '0'
			if digit <= 9 && isKnownDomainPrefix(address, colon) {
				return address[:colon], net.Port(digit), true
			}
		}
	}
	colon := bytes.IndexByte(address, ':')
	if colon <= 0 {
		return nil, 0, false
	}
	port, ok := parseServerPort(string(address[colon+1:]))
	if !ok {
		return nil, 0, false
	}
	return address[:colon], port, true
}

func isKnownDomainPrefix(address []byte, colon int) bool {
	return colon > 0 && bytes.IndexByte(address[:colon], ':') < 0
}

func parseUDPDestination(address string) (net.Destination, error) {
	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		return net.Destination{}, err
	}
	parsedAddress := net.AnyIP
	if len(host) > 0 {
		parsedAddress = net.ParseAddress(host)
	}
	var port net.Port
	if len(portString) > 0 {
		port, err = net.PortFromString(portString)
		if err != nil {
			return net.Destination{}, err
		}
	}
	return net.UDPDestination(parsedAddress, port), nil
}

func parseUDPDestinationBytes(address []byte) (net.Destination, error) {
	if destination, ok := parseIPv4UDPDestination(address); ok {
		return destination, nil
	}
	return parseUDPDestination(string(address))
}

func parseIPv4UDPDestination(address []byte) (net.Destination, bool) {
	ip, port, ok := parseIPv4UDPAddress(address)
	if !ok {
		return net.Destination{}, false
	}
	return net.UDPDestination(net.IPv4Address(ip), port), true
}

func parseIPv4UDPAddress(address []byte) ([4]byte, net.Port, bool) {
	if ip, port, ok := parseCanonicalIPv4UDPAddress(address); ok {
		return ip, port, true
	}
	return parseIPv4UDPAddressFallback(address)
}

func parseCanonicalIPv4UDPAddress(address []byte) ([4]byte, net.Port, bool) {
	if len(address) < len("0.0.0.0:0") || len(address) > len("255.255.255.255:65535") {
		return [4]byte{}, 0, false
	}
	var ip [4]byte
	index := 0
	var ok bool
	ip[0], index, ok = parseCanonicalIPv4Octet(address, index, '.')
	if !ok {
		return [4]byte{}, 0, false
	}
	ip[1], index, ok = parseCanonicalIPv4Octet(address, index, '.')
	if !ok {
		return [4]byte{}, 0, false
	}
	ip[2], index, ok = parseCanonicalIPv4Octet(address, index, '.')
	if !ok {
		return [4]byte{}, 0, false
	}
	ip[3], index, ok = parseCanonicalIPv4Octet(address, index, ':')
	if !ok {
		return [4]byte{}, 0, false
	}
	if index >= len(address) || len(address)-index > 5 {
		return [4]byte{}, 0, false
	}
	switch len(address) - index {
	case 1:
		digit := address[index] - '0'
		if digit <= 9 {
			return ip, net.Port(digit), true
		}
	case 2:
		tens, ones := address[index]-'0', address[index+1]-'0'
		if tens <= 9 && ones <= 9 {
			return ip, net.Port(tens)*10 + net.Port(ones), true
		}
	case 3:
		hundreds, tens, ones := address[index]-'0', address[index+1]-'0', address[index+2]-'0'
		if hundreds <= 9 && tens <= 9 && ones <= 9 {
			return ip, net.Port(hundreds)*100 + net.Port(tens)*10 + net.Port(ones), true
		}
	case 4:
		thousands, hundreds := address[index]-'0', address[index+1]-'0'
		tens, ones := address[index+2]-'0', address[index+3]-'0'
		if thousands <= 9 && hundreds <= 9 && tens <= 9 && ones <= 9 {
			return ip, net.Port(thousands)*1000 + net.Port(hundreds)*100 + net.Port(tens)*10 + net.Port(ones), true
		}
	case 5:
		tenThousands, thousands := address[index]-'0', address[index+1]-'0'
		hundreds, tens, ones := address[index+2]-'0', address[index+3]-'0', address[index+4]-'0'
		if tenThousands <= 9 && thousands <= 9 && hundreds <= 9 && tens <= 9 && ones <= 9 {
			value := uint32(tenThousands)*10000 + uint32(thousands)*1000 + uint32(hundreds)*100 + uint32(tens)*10 + uint32(ones)
			if value <= 65535 {
				return ip, net.Port(value), true
			}
		}
	}
	return [4]byte{}, 0, false
}

func parseCanonicalIPv4Octet(address []byte, index int, separator byte) (byte, int, bool) {
	if index >= len(address) {
		return 0, 0, false
	}
	character := address[index]
	if character < '0' || character > '9' {
		return 0, 0, false
	}
	value := int(character - '0')
	index++
	if index >= len(address) {
		return 0, 0, false
	}
	if address[index] == separator {
		return byte(value), index + 1, true
	}
	character = address[index]
	if character < '0' || character > '9' {
		return 0, 0, false
	}
	value = value*10 + int(character-'0')
	index++
	if index >= len(address) {
		return 0, 0, false
	}
	if address[index] == separator {
		return byte(value), index + 1, true
	}
	character = address[index]
	if character < '0' || character > '9' {
		return 0, 0, false
	}
	value = value*10 + int(character-'0')
	index++
	if value > 255 || index >= len(address) || address[index] != separator {
		return 0, 0, false
	}
	return byte(value), index + 1, true
}

func parseIPv4UDPAddressFallback(address []byte) ([4]byte, net.Port, bool) {
	var ip [4]byte
	octet := 0
	value := 0
	digits := 0
	colon := -1
	for index, character := range address {
		switch {
		case character >= '0' && character <= '9':
			value = value*10 + int(character-'0')
			digits++
			if value > 255 {
				return [4]byte{}, 0, false
			}
		case character == '.' && octet < 3 && digits > 0:
			ip[octet] = byte(value)
			octet++
			value, digits = 0, 0
		case character == ':' && octet == 3 && digits > 0:
			ip[octet] = byte(value)
			colon = index
		default:
			return [4]byte{}, 0, false
		}
		if colon >= 0 {
			break
		}
	}
	if colon < 0 || colon+1 == len(address) {
		return [4]byte{}, 0, false
	}
	port := 0
	for _, character := range address[colon+1:] {
		if character < '0' || character > '9' {
			return [4]byte{}, 0, false
		}
		port = port*10 + int(character-'0')
		if port > 65535 {
			return [4]byte{}, 0, false
		}
	}
	return ip, net.Port(port), true
}

func (r *UDPReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.firstBuf != nil {
		mb := r.firstBuf.SingleMultiBuffer()
		r.firstBuf = nil
		return mb, nil
	}
	b, _, err := r.readBufferPacket()
	if err != nil {
		return nil, err
	}
	return b.SingleMultiBuffer(), nil
}

func (r *UDPReader) readBufferPacket() (*buf.Buffer, udpPacketDestination, error) {
	b := buf.New()
	for {
		b.Clear()
		if _, err := b.ReadFrom(r.reader); err != nil {
			b.Release()
			return nil, udpPacketDestination{}, err
		}

		frame := b.Bytes()
		address, err := parseUDPMessageFields(frame, &r.message)
		if err != nil {
			continue
		}
		msg := &r.message
		var destination udpPacketDestination
		if msg.FragCount > 1 {
			fragment := r.message
			if !r.df.storeClonedFragment(&fragment) {
				continue
			}
			destination, err = r.parseFragmentDestination(address)
			if err != nil {
				r.df.reset()
				continue
			}
			if r.df.size > int(b.Cap()) {
				r.df.reset()
				b.Release()
				return nil, udpPacketDestination{}, buf.ErrBufferFull
			}
			b.Clear()
			msg = r.df.assemble(&fragment, b.Extend(int32(r.df.size)))
		} else {
			first := address[0]
			if first >= '0' && first <= '9' {
				ip, port, ok := parseCanonicalIPv4UDPAddress(address)
				if !ok {
					ip, port, ok = parseIPv4UDPAddressFallback(address)
				}
				if ok {
					destination.ipv4 = ip
					destination.port = port
					destination.isIPv4 = true
				} else {
					destination.destination, err = parseUDPDestination(string(address))
					if err != nil {
						continue
					}
				}
			} else if folded := first | 0x20; folded-'a' <= 'z'-'a' {
				if domainBytes, port, ok := parseKnownDomainUDPAddress(address); ok {
					domain := r.lastDomain
					if port != r.lastDomainPort || string(domainBytes) != domain {
						r.lastAddress = string(address)
						domain = r.lastAddress[:len(domainBytes)]
						r.lastDomain = domain
						r.lastDomainPort = port
					}
					b.SetManagedUDPDomain(domain, port)
					destination.domain = domain
					destination.port = port
					destination.isDomain = true
					destination.managed = true
				} else {
					destination.destination, err = parseUDPDestination(string(address))
					if err != nil {
						continue
					}
				}
			} else {
				destination.destination, err = parseUDPDestination(string(address))
				if err != nil {
					continue
				}
			}
			b.Advance(int32(len(frame) - len(msg.Data)))
		}
		destination.SetBufferDestination(b)
		return b, destination, nil
	}
}

func (r *UDPReader) parseFragmentDestination(address []byte) (udpPacketDestination, error) {
	first := address[0]
	if first >= '0' && first <= '9' {
		ip, port, ok := parseCanonicalIPv4UDPAddress(address)
		if !ok {
			ip, port, ok = parseIPv4UDPAddressFallback(address)
		}
		if ok {
			return udpPacketDestination{ipv4: ip, port: port, isIPv4: true}, nil
		}
	} else if folded := first | 0x20; folded-'a' <= 'z'-'a' {
		if domainBytes, port, ok := parseKnownDomainUDPAddress(address); ok {
			domain := r.lastDomain
			if port != r.lastDomainPort || string(domainBytes) != domain {
				r.lastAddress = string(address)
				domain = r.lastAddress[:len(domainBytes)]
				r.lastDomain = domain
				r.lastDomainPort = port
			}
			return udpPacketDestination{domain: domain, port: port, isDomain: true}, nil
		}
	}
	destination, err := parseUDPDestination(string(address))
	return udpPacketDestination{destination: destination}, err
}
