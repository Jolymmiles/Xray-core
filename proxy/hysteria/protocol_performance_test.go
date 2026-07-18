package hysteria

import (
	"bytes"
	"encoding/binary"
	stderrors "errors"
	"fmt"
	"io"
	"testing"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

var (
	parsedUDPMessageSink *UDPMessage
	parsedUDPValueSink   UDPMessage
	udpAddressBytesSink  []byte
	tcpAddressSink       string
	udpDestinationSink   *net.Destination
	tcpDestinationSink   net.Destination
	udpMultiBufferSink   buf.MultiBuffer
	udpIPv4Sink          [4]byte
	udpPortSink          net.Port
)

func benchmarkParseServerPortLoop(port string) (net.Port, bool) {
	value := 0
	for index := range len(port) {
		digit := port[index]
		if digit < '0' || digit > '9' {
			return 0, false
		}
		value = value*10 + int(digit-'0')
		if value > 65535 {
			return 0, false
		}
	}
	return net.Port(value), true
}

func BenchmarkParseServerPort443(b *testing.B) {
	for _, benchmark := range []struct {
		name  string
		parse func(string) (net.Port, bool)
	}{
		{name: "loop", parse: benchmarkParseServerPortLoop},
		{name: "unrolled", parse: parseServerPort},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			for b.Loop() {
				udpPortSink, _ = benchmark.parse("443")
			}
		})
	}
}

func BenchmarkParseServerPort80(b *testing.B) {
	for _, benchmark := range []struct {
		name  string
		parse func(string) (net.Port, bool)
	}{
		{name: "loop", parse: benchmarkParseServerPortLoop},
		{name: "unrolled", parse: parseServerPort},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			for b.Loop() {
				udpPortSink, _ = benchmark.parse("80")
			}
		})
	}
}

func BenchmarkParseServerPort8443(b *testing.B) {
	for _, benchmark := range []struct {
		name  string
		parse func(string) (net.Port, bool)
	}{
		{name: "loop", parse: benchmarkParseServerPortLoop},
		{name: "unrolled", parse: parseServerPort},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			for b.Loop() {
				udpPortSink, _ = benchmark.parse("8443")
			}
		})
	}
}

func BenchmarkParseServerPort65535(b *testing.B) {
	for _, benchmark := range []struct {
		name  string
		parse func(string) (net.Port, bool)
	}{
		{name: "loop", parse: benchmarkParseServerPortLoop},
		{name: "unrolled", parse: parseServerPort},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			for b.Loop() {
				udpPortSink, _ = benchmark.parse("65535")
			}
		})
	}
}

func BenchmarkParseServerPort8(b *testing.B) {
	for _, benchmark := range []struct {
		name  string
		parse func(string) (net.Port, bool)
	}{
		{name: "loop", parse: benchmarkParseServerPortLoop},
		{name: "unrolled", parse: parseServerPort},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			for b.Loop() {
				udpPortSink, _ = benchmark.parse("8")
			}
		})
	}
}

type repeatedDatagramReader []byte

func (r repeatedDatagramReader) Read(payload []byte) (int, error) {
	return copy(payload, r), nil
}

type sequentialDatagramReader struct {
	messages [][]byte
	index    int
}

type oneByteReader struct {
	data []byte
}

type readerOnly struct{ io.Reader }

func BenchmarkServerQUICVarintReaderOnly(b *testing.B) {
	for _, value := range []uint64{15, 256, 16384, 1 << 32} {
		wire := quicvarint.Append(nil, value)
		b.Run(fmt.Sprintf("%d/library", value), func(b *testing.B) {
			var source bytes.Reader
			wrapped := &readerOnly{Reader: &source}
			b.ReportAllocs()
			for b.Loop() {
				source.Reset(wire)
				parsed, err := quicvarint.Read(quicvarint.NewReader(wrapped))
				if err != nil || parsed != value {
					b.Fatalf("parsed=%d err=%v", parsed, err)
				}
			}
		})
		b.Run(fmt.Sprintf("%d/bulk", value), func(b *testing.B) {
			var source bytes.Reader
			wrapped := &readerOnly{Reader: &source}
			var scratch [8]byte
			b.ReportAllocs()
			for b.Loop() {
				source.Reset(wire)
				parsed, err := readServerQUICVarint(wrapped, nil, &scratch)
				if err != nil || parsed != value {
					b.Fatalf("parsed=%d err=%v", parsed, err)
				}
			}
		})
	}
}

func (r *oneByteReader) Read(payload []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	payload[0] = r.data[0]
	r.data = r.data[1:]
	return 1, nil
}

func (r *sequentialDatagramReader) Read(payload []byte) (int, error) {
	if r.index >= len(r.messages) {
		return 0, io.EOF
	}
	message := r.messages[r.index]
	r.index++
	return copy(payload, message), nil
}

func hysteriaUDPWire(address string, payload []byte) []byte {
	var addressLength [8]byte
	lengthSize := varintPut(addressLength[:], uint64(len(address)))
	wire := make([]byte, 8+lengthSize+len(address)+len(payload))
	binary.BigEndian.PutUint32(wire, 0x01020304)
	binary.BigEndian.PutUint16(wire[4:], 0x0506)
	wire[6] = 0
	wire[7] = 1
	copy(wire[8:], addressLength[:lengthSize])
	copy(wire[8+lengthSize:], address)
	copy(wire[8+lengthSize+len(address):], payload)
	return wire
}

func TestParseUDPMessagePreservesWireFields(t *testing.T) {
	payload := []byte("hysteria-udp-payload")
	message, err := ParseUDPMessage(hysteriaUDPWire("example.com:443", payload))
	if err != nil {
		t.Fatal(err)
	}
	if message.SessionID != 0x01020304 || message.PacketID != 0x0506 || message.FragID != 0 || message.FragCount != 1 {
		t.Fatalf("unexpected message header: %+v", message)
	}
	if message.Addr != "example.com:443" || !bytes.Equal(message.Data, payload) {
		t.Fatalf("message = (%q, %q), want (%q, %q)", message.Addr, message.Data, "example.com:443", payload)
	}
}

func TestParseUDPMessageFieldsRejectsMissingAddressLength(t *testing.T) {
	var parsed UDPMessage
	if _, err := parseUDPMessageFields(make([]byte, 8), &parsed); err == nil {
		t.Fatal("8-byte UDP header without address length was accepted")
	}
}

func TestParseUDPMessageAcceptsMultiByteAddressLength(t *testing.T) {
	address := string(bytes.Repeat([]byte{'a'}, 64))
	message, err := ParseUDPMessage(hysteriaUDPWire(address, []byte("payload")))
	if err != nil {
		t.Fatal(err)
	}
	if message.Addr != address || string(message.Data) != "payload" {
		t.Fatalf("message address length=%d payload=%q", len(message.Addr), message.Data)
	}
}

func TestParseUDPMessageAllocationBudget(t *testing.T) {
	wire := hysteriaUDPWire("example.com:443", make([]byte, 1150))
	allocations := testing.AllocsPerRun(1000, func() {
		message, err := ParseUDPMessage(wire)
		if err != nil {
			t.Fatal(err)
		}
		parsedUDPMessageSink = message
	})
	if allocations > 2 {
		t.Fatalf("ParseUDPMessage allocations = %.0f, want at most 2", allocations)
	}
}

func TestReadTCPRequestPreservesAddress(t *testing.T) {
	wire := append([]byte{15}, []byte("example.com:443")...)
	wire = append(wire, 0)
	address, err := ReadTCPRequest(bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	if address != "example.com:443" {
		t.Fatalf("address = %q, want example.com:443", address)
	}
}

func TestReadTCPRequestAcceptsFragmentedVarintsAndPadding(t *testing.T) {
	address := "example.com:443"
	wire := make([]byte, 1+len(address)+2+256)
	wire[0] = byte(len(address))
	copy(wire[1:], address)
	varintPut(wire[1+len(address):], 256)
	parsed, err := ReadTCPRequest(&oneByteReader{data: wire})
	if err != nil {
		t.Fatal(err)
	}
	if parsed != address {
		t.Fatalf("address = %q, want %q", parsed, address)
	}
}

func TestReadTCPRequestAllocationBudget(t *testing.T) {
	wire := append([]byte{15}, []byte("example.com:443")...)
	wire = append(wire, 0)
	reader := bytes.NewReader(wire)
	allocations := testing.AllocsPerRun(1000, func() {
		reader.Reset(wire)
		address, err := ReadTCPRequest(reader)
		if err != nil {
			t.Fatal(err)
		}
		tcpAddressSink = address
	})
	if allocations > 1 {
		t.Fatalf("ReadTCPRequest allocations = %.0f, want at most 1", allocations)
	}
}

func TestReadTCPRequestPaddedAllocationBudget(t *testing.T) {
	address := "example.com:443"
	wire := make([]byte, 1+len(address)+2+256)
	wire[0] = byte(len(address))
	copy(wire[1:], address)
	varintPut(wire[1+len(address):], 256)
	reader := bytes.NewReader(wire)
	allocations := testing.AllocsPerRun(1000, func() {
		reader.Reset(wire)
		parsedAddress, err := ReadTCPRequest(reader)
		if err != nil {
			t.Fatal(err)
		}
		tcpAddressSink = parsedAddress
	})
	if allocations > 1 {
		t.Fatalf("padded ReadTCPRequest allocations = %.0f, want at most 1", allocations)
	}
}

func TestParseServerTCPDestination(t *testing.T) {
	for _, test := range []struct {
		input   string
		address string
		port    net.Port
	}{
		{input: "example.com:443", address: "example.com", port: 443},
		{input: "127.0.0.1:80", address: "127.0.0.1", port: 80},
		{input: "[2001:db8::1]:8443", address: "[2001:db8::1]", port: 8443},
		{input: ":53", address: "0.0.0.0", port: 53},
	} {
		t.Run(test.input, func(t *testing.T) {
			destination, err := parseServerTCPDestination(test.input)
			if err != nil {
				t.Fatal(err)
			}
			if destination.Network != net.Network_TCP || destination.Address.String() != test.address || destination.Port != test.port {
				t.Fatalf("destination = %v, want tcp:%s:%d", destination, test.address, test.port)
			}
		})
	}
}

func TestParseServerTCPDestinationPreservesFallbackSyntax(t *testing.T) {
	if _, err := parseServerTCPDestination("example.com:+443"); err == nil {
		t.Fatal("signed port was accepted")
	}
	destination, err := parseServerTCPDestination("[2001:db8::1]:8443")
	if err != nil {
		t.Fatal(err)
	}
	if !destination.IsValid() || !destination.Address.Family().IsIPv6() || destination.Port != 8443 {
		t.Fatalf("IPv6 fallback destination = %+v", destination)
	}
}

func TestParseServerTCPDestinationAllocationBudget(t *testing.T) {
	allocations := testing.AllocsPerRun(1000, func() {
		destination, err := parseServerTCPDestination("example.com:443")
		if err != nil {
			t.Fatal(err)
		}
		tcpDestinationSink = destination
	})
	if allocations > 1 {
		t.Fatalf("parseServerTCPDestination allocations = %.0f, want at most 1", allocations)
	}
}

func TestReadServerTCPRequestDestination(t *testing.T) {
	for _, test := range []struct {
		address string
		want    string
		ok      bool
	}{
		{address: "example.com:443", want: "tcp:example.com:443", ok: true},
		{address: "127.0.0.1:80", want: "tcp:127.0.0.1:80", ok: true},
		{address: "[2001:db8::1]:8443", want: "tcp:[2001:db8::1]:8443", ok: true},
		{address: ":53", want: "tcp:0.0.0.0:53", ok: true},
		{address: "example.com:+443", ok: false},
	} {
		t.Run(test.address, func(t *testing.T) {
			wire := append([]byte{byte(len(test.address))}, test.address...)
			wire = append(wire, 0)
			request, err := readServerTCPRequest(bytes.NewReader(wire))
			if (err == nil) != test.ok {
				t.Fatalf("readServerTCPRequest() error = %v, want success %t", err, test.ok)
			}
			if request == nil {
				return
			}
			defer releaseServerTCPRequest(request)
			if got := request.destination.String(); got != test.want {
				t.Fatalf("destination = %q, want %q", got, test.want)
			}
		})
	}
}

func TestReadServerTCPRequestAddressReuse(t *testing.T) {
	for _, address := range []string{"2001.invalid:443", "[2001:db8::1]:443", "192.0.2.1:443", "next.example:8443"} {
		wire := append([]byte{byte(len(address))}, address...)
		wire = append(wire, 0)
		request, err := readServerTCPRequest(bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		if got := request.destination.String(); got != "tcp:"+address {
			t.Fatalf("reused destination = %q, want %q", got, "tcp:"+address)
		}
		releaseServerTCPRequest(request)
	}
}

func TestReadServerTCPRequestAllocationBudget(t *testing.T) {
	wire := append([]byte{15}, []byte("example.com:443")...)
	wire = append(wire, 0)
	reader := bytes.NewReader(wire)
	allocations := testing.AllocsPerRun(1000, func() {
		reader.Reset(wire)
		request, err := readServerTCPRequest(reader)
		if err != nil {
			t.Fatal(err)
		}
		tcpDestinationSink = request.destination
		releaseServerTCPRequest(request)
	})
	if allocations != 0 {
		t.Fatalf("server TCP request allocations = %.0f, want zero", allocations)
	}
}

func TestReadServerTCPRequestPaddedAllocationBudget(t *testing.T) {
	address := "example.com:443"
	wire := make([]byte, 1+len(address)+2+256)
	wire[0] = byte(len(address))
	copy(wire[1:], address)
	varintPut(wire[1+len(address):], 256)
	reader := bytes.NewReader(wire)
	allocations := testing.AllocsPerRun(1000, func() {
		reader.Reset(wire)
		request, err := readServerTCPRequest(reader)
		if err != nil {
			t.Fatal(err)
		}
		tcpDestinationSink = request.destination
		releaseServerTCPRequest(request)
	})
	if allocations != 0 {
		t.Fatalf("padded server TCP request allocations = %.0f, want zero", allocations)
	}
}

func TestWriteTCPResponseRoundTrip(t *testing.T) {
	var wire bytes.Buffer
	if err := WriteTCPResponse(&wire, false, "upstream unavailable"); err != nil {
		t.Fatal(err)
	}
	ok, message, err := ReadTCPResponse(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if ok || message != "upstream unavailable" {
		t.Fatalf("response = (%v, %q), want (false, %q)", ok, message, "upstream unavailable")
	}
}

func TestWriteTCPResponseOKRoundTrip(t *testing.T) {
	var wire bytes.Buffer
	if err := writeTCPResponseOK(&wire); err != nil {
		t.Fatal(err)
	}
	ok, message, err := ReadTCPResponse(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || message != "" {
		t.Fatalf("response = ok:%t message:%q, want ok with empty message", ok, message)
	}
}

func TestWriteTCPResponseAllocationBudget(t *testing.T) {
	allocations := testing.AllocsPerRun(1000, func() {
		if err := WriteTCPResponse(io.Discard, true, ""); err != nil {
			t.Fatal(err)
		}
	})
	if allocations != 0 {
		t.Fatalf("WriteTCPResponse allocations = %.0f, want 0", allocations)
	}
}

func BenchmarkParseUDPMessage(b *testing.B) {
	wire := hysteriaUDPWire("example.com:443", make([]byte, 1150))
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		message, err := ParseUDPMessage(wire)
		if err != nil {
			b.Fatal(err)
		}
		parsedUDPMessageSink = message
	}
}

func BenchmarkParseUDPMessageFields(b *testing.B) {
	wire := hysteriaUDPWire("127.0.0.1:443", make([]byte, 1100))
	var parsed UDPMessage
	b.ReportAllocs()
	for b.Loop() {
		address, err := parseUDPMessageFields(wire, &parsed)
		if err != nil {
			b.Fatal(err)
		}
		udpAddressBytesSink = address
		parsedUDPValueSink = parsed
	}
}

func TestDefraggerSmallPacketAllocationBudget(t *testing.T) {
	firstData, secondData := []byte("first-"), []byte("second")
	first := UDPMessage{PacketID: 7, FragID: 0, FragCount: 2, Data: firstData}
	second := UDPMessage{PacketID: 7, FragID: 1, FragCount: 2, Data: secondData}
	allocations := testing.AllocsPerRun(1000, func() {
		var defragger Defragger
		first.FragID, first.FragCount = 0, 2
		second.FragID, second.FragCount = 1, 2
		first.Data, second.Data = firstData, secondData
		if defragger.Feed(&first) != nil {
			t.Fatal("first fragment completed packet")
		}
		message := defragger.Feed(&second)
		if message == nil || string(message.Data) != "first-second" {
			t.Fatalf("defragmented message = %v", message)
		}
	})
	if allocations > 1 {
		t.Fatalf("two-fragment Defragger allocations = %.0f, want at most assembly allocation", allocations)
	}
	var defragger Defragger
	first.FragID, first.FragCount, first.Data = 0, 2, firstData
	second.FragID, second.FragCount, second.Data = 1, 2, secondData
	defragger.Feed(&first)
	defragger.Feed(&second)
	if defragger.fragCount != 0 || defragger.count != 0 || defragger.size != 0 || len(defragger.frags) != 0 {
		t.Fatalf("completed Defragger retained state: %+v", defragger)
	}
	for index, fragment := range defragger.small {
		if fragment != nil {
			t.Fatalf("completed Defragger retained small fragment %d", index)
		}
	}
}

func BenchmarkDefraggerTwoFragments(b *testing.B) {
	firstData, secondData := []byte("first-"), []byte("second")
	first := UDPMessage{PacketID: 7, Data: firstData}
	second := UDPMessage{PacketID: 7, Data: secondData}
	b.ReportAllocs()
	for b.Loop() {
		var defragger Defragger
		first.FragID, first.FragCount = 0, 2
		second.FragID, second.FragCount = 1, 2
		first.Data, second.Data = firstData, secondData
		defragger.Feed(&first)
		parsedUDPMessageSink = defragger.Feed(&second)
	}
}

func BenchmarkUDPReaderReadMultiBufferFragments(b *testing.B) {
	first := hysteriaUDPWire("127.0.0.1:443", bytes.Repeat([]byte{'a'}, 550))
	second := hysteriaUDPWire("127.0.0.1:443", bytes.Repeat([]byte{'b'}, 550))
	binary.BigEndian.PutUint16(first[4:], 7)
	binary.BigEndian.PutUint16(second[4:], 7)
	first[6], first[7] = 0, 2
	second[6], second[7] = 1, 2
	source := &sequentialDatagramReader{messages: [][]byte{first, second}}
	reader := &UDPReader{reader: source}
	b.ReportAllocs()
	b.SetBytes(1100)
	for b.Loop() {
		source.index = 0
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			b.Fatal(err)
		}
		udpMultiBufferSink = mb
		buf.ReleaseMulti(mb)
	}
}

func BenchmarkUDPReaderReadFromDestinationFragments(b *testing.B) {
	first := hysteriaUDPWire("127.0.0.1:443", bytes.Repeat([]byte{'a'}, 550))
	second := hysteriaUDPWire("127.0.0.1:443", bytes.Repeat([]byte{'b'}, 550))
	binary.BigEndian.PutUint16(first[4:], 7)
	binary.BigEndian.PutUint16(second[4:], 7)
	first[6], first[7] = 0, 2
	second[6], second[7] = 1, 2
	source := &sequentialDatagramReader{messages: [][]byte{first, second}}
	reader := &UDPReader{reader: source}
	payload := make([]byte, 1200)
	b.ReportAllocs()
	b.SetBytes(1100)
	for b.Loop() {
		source.index = 0
		n, destination, err := reader.readFromDestination(payload)
		if err != nil {
			b.Fatal(err)
		}
		if n != 1100 {
			b.Fatalf("payload length = %d, want 1100", n)
		}
		tcpDestinationSink = destination
	}
}

func BenchmarkUDPReaderReadFrom(b *testing.B) {
	wire := hysteriaUDPWire("127.0.0.1:443", make([]byte, 1100))
	reader := &UDPReader{reader: repeatedDatagramReader(wire)}
	payload := make([]byte, 2048)
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		n, destination, err := reader.ReadFrom(payload)
		if err != nil {
			b.Fatal(err)
		}
		if n != 1100 {
			b.Fatalf("payload length = %d, want 1100", n)
		}
		udpDestinationSink = destination
	}
}

func BenchmarkUDPReaderReadFromDestination(b *testing.B) {
	wire := hysteriaUDPWire("127.0.0.1:443", make([]byte, 1100))
	reader := &UDPReader{reader: repeatedDatagramReader(wire)}
	payload := make([]byte, 2048)
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		n, destination, err := reader.readFromDestination(payload)
		if err != nil {
			b.Fatal(err)
		}
		if n != 1100 {
			b.Fatalf("payload length = %d, want 1100", n)
		}
		tcpDestinationSink = destination
	}
}

func BenchmarkUDPReaderReadMultiBuffer(b *testing.B) {
	wire := hysteriaUDPWire("127.0.0.1:443", make([]byte, 1100))
	reader := &UDPReader{reader: repeatedDatagramReader(wire)}
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			b.Fatal(err)
		}
		udpMultiBufferSink = mb
		buf.ReleaseMulti(mb)
	}
}

func BenchmarkUDPReaderReadMultiBufferDomain(b *testing.B) {
	wire := hysteriaUDPWire("example.com:443", make([]byte, 1100))
	reader := &UDPReader{reader: repeatedDatagramReader(wire)}
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			b.Fatal(err)
		}
		udpMultiBufferSink = mb
		buf.ReleaseMulti(mb)
	}
}

func TestUDPReaderDomainCacheTracksAddressAndPort(t *testing.T) {
	addresses := []string{"first.example:443", "second.example:8443", "first.example:443"}
	messages := make([][]byte, len(addresses))
	for index, address := range addresses {
		messages[index] = hysteriaUDPWire(address, []byte("payload"))
	}
	reader := &UDPReader{reader: &sequentialDatagramReader{messages: messages}}
	for _, want := range addresses {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		if len(mb) != 1 || mb[0].UDP == nil || mb[0].UDP.NetAddr() != want {
			buf.ReleaseMulti(mb)
			t.Fatalf("destination = %v, want %q", mb, want)
		}
		buf.ReleaseMulti(mb)
	}
}

func TestParseUDPDomainAddressRejectsMultipleColons(t *testing.T) {
	if _, _, ok := parseKnownDomainUDPAddress([]byte("example.com:extra:443")); ok {
		t.Fatal("domain with multiple colons was accepted")
	}
}

func TestUDPReaderServerPacketDestinationOwnsDomain(t *testing.T) {
	reader := new(UDPReader)
	destination := reader.serverPacketDestination(udpPacketDestination{
		domain: "example.com", port: 443, isDomain: true,
	})
	if destination.NetAddr() != "example.com:443" {
		t.Fatalf("destination = %q, want example.com:443", destination.NetAddr())
	}
}

func BenchmarkUDPReaderServerPacketDestination(b *testing.B) {
	reader := new(UDPReader)
	packetDestination := udpPacketDestination{domain: "example.com", port: 443, isDomain: true}
	b.ReportAllocs()
	for b.Loop() {
		tcpDestinationSink = reader.serverPacketDestination(packetDestination)
	}
}

func BenchmarkUDPReaderServerPacketDestinationBaseline(b *testing.B) {
	packetDestination := udpPacketDestination{domain: "example.com", port: 443, isDomain: true}
	b.ReportAllocs()
	for b.Loop() {
		tcpDestinationSink = packetDestination.Destination()
	}
}

func TestUDPReaderServerPacketDestinationOwnsIPv4(t *testing.T) {
	reader := new(UDPReader)
	destination := reader.serverPacketDestination(udpPacketDestination{
		ipv4: [4]byte{192, 0, 2, 1}, port: 443, isIPv4: true,
	})
	if destination.NetAddr() != "192.0.2.1:443" {
		t.Fatalf("destination = %q, want 192.0.2.1:443", destination.NetAddr())
	}
}

func BenchmarkUDPReaderServerPacketDestinationIPv4(b *testing.B) {
	reader := new(UDPReader)
	packetDestination := udpPacketDestination{ipv4: [4]byte{192, 0, 2, 1}, port: 443, isIPv4: true}
	b.ReportAllocs()
	for b.Loop() {
		tcpDestinationSink = reader.serverPacketDestination(packetDestination)
	}
}

func BenchmarkUDPReaderServerPacketDestinationIPv4Baseline(b *testing.B) {
	packetDestination := udpPacketDestination{ipv4: [4]byte{192, 0, 2, 1}, port: 443, isIPv4: true}
	b.ReportAllocs()
	for b.Loop() {
		tcpDestinationSink = packetDestination.Destination()
	}
}

func TestUDPReaderServerPacketAddressReusesOwnedDomain(t *testing.T) {
	reader := &UDPReader{
		lastDomain: "example.com", lastDomainPort: 443, lastAddress: "example.com:443",
	}
	packetDestination := udpPacketDestination{domain: "example.com", port: 443, isDomain: true}
	if got := reader.serverPacketAddress(packetDestination); got != "example.com:443" {
		t.Fatalf("serverPacketAddress() = %q, want example.com:443", got)
	}
}

func BenchmarkUDPReaderServerPacketAddress(b *testing.B) {
	reader := &UDPReader{
		lastDomain: "example.com", lastDomainPort: 443, lastAddress: "example.com:443",
	}
	packetDestination := udpPacketDestination{domain: "example.com", port: 443, isDomain: true}
	b.ReportAllocs()
	for b.Loop() {
		tcpAddressSink = reader.serverPacketAddress(packetDestination)
	}
}

func BenchmarkUDPReaderServerPacketAddressBaseline(b *testing.B) {
	reader := new(UDPReader)
	packetDestination := udpPacketDestination{domain: "example.com", port: 443, isDomain: true}
	b.ReportAllocs()
	for b.Loop() {
		tcpAddressSink = reader.serverPacketDestination(packetDestination).NetAddr()
	}
}

func TestParseIPv4UDPAddressPreservesPermissiveForms(t *testing.T) {
	for _, address := range []string{
		"127.0.0.1:443",
		"0001.0002.0003.0004:00053",
		"255.255.255.255:65535",
	} {
		if _, _, ok := parseIPv4UDPAddress([]byte(address)); !ok {
			t.Fatalf("valid address %q was rejected", address)
		}
	}
	for _, address := range []string{
		"256.0.0.1:443",
		"127.0.0.1:65536",
		"127.0.0.1:",
		"example.com:443",
	} {
		if _, _, ok := parseIPv4UDPAddress([]byte(address)); ok {
			t.Fatalf("invalid address %q was accepted", address)
		}
	}
}

func TestParseCanonicalIPv4UDPAddressMatchesFallback(t *testing.T) {
	valid := []string{
		"0.0.0.0:0",
		"1.2.3.4:9",
		"10.20.30.40:53",
		"127.0.0.1:443",
		"192.168.100.200:65535",
		"255.255.255.255:65535",
	}
	for _, address := range valid {
		gotIP, gotPort, gotOK := parseCanonicalIPv4UDPAddress([]byte(address))
		wantIP, wantPort, wantOK := parseIPv4UDPAddressFallback([]byte(address))
		if gotIP != wantIP || gotPort != wantPort || gotOK != wantOK {
			t.Fatalf("parseCanonicalIPv4UDPAddress(%q) = %v, %d, %v; fallback = %v, %d, %v", address, gotIP, gotPort, gotOK, wantIP, wantPort, wantOK)
		}
	}
	invalid := []string{
		"", "1.2.3.4", "1.2.3.4:", "1.2.3:4", "1.2.3.4.5:6",
		"1..2.3:4", "1.2.3.256:4", "1.2.3.4:65536", "1.2.3.4:-1",
	}
	for _, address := range invalid {
		if _, _, ok := parseCanonicalIPv4UDPAddress([]byte(address)); ok {
			t.Fatalf("parseCanonicalIPv4UDPAddress(%q) unexpectedly succeeded", address)
		}
	}
}

func BenchmarkParseIPv4UDPAddress(b *testing.B) {
	for _, address := range []string{"127.0.0.1:9", "127.0.0.1:53", "127.0.0.1:443", "127.0.0.1:5353", "127.0.0.1:65535"} {
		b.Run(address, func(b *testing.B) {
			wireAddress := []byte(address)
			b.ReportAllocs()
			for b.Loop() {
				ip, port, ok := parseIPv4UDPAddress(wireAddress)
				if !ok {
					b.Fatal("canonical IPv4 address was rejected")
				}
				udpIPv4Sink = ip
				udpPortSink = port
			}
		})
	}
}

func TestParseKnownDomainUDPAddress(t *testing.T) {
	for _, test := range []struct {
		address string
		domain  string
		port    net.Port
		ok      bool
	}{
		{address: "example.com:443", domain: "example.com", port: 443, ok: true},
		{address: "a:0", domain: "a", port: 0, ok: true},
		{address: "dns.example:53", domain: "dns.example", port: 53, ok: true},
		{address: "mdns.example:5353", domain: "mdns.example", port: 5353, ok: true},
		{address: "example.com:65535", domain: "example.com", port: 65535, ok: true},
		{address: "[2001:db8::1]:443"},
		{address: ":443"},
		{address: "example.com"},
		{address: "example.com:", domain: "example.com", port: 0, ok: true},
		{address: "example.com:65536"},
		{address: "example.com:abc"},
	} {
		domain, port, ok := parseKnownDomainUDPAddress([]byte(test.address))
		if string(domain) != test.domain || port != test.port || ok != test.ok {
			t.Fatalf("parseKnownDomainUDPAddress(%q) = %q, %d, %v; want %q, %d, %v", test.address, domain, port, ok, test.domain, test.port, test.ok)
		}
	}
}

func BenchmarkParseKnownDomainUDPAddress(b *testing.B) {
	for _, address := range []string{"example.com:", "example.com:9", "example.com:53", "example.com:443", "example.com:5353", "example.com:65535"} {
		b.Run(address, func(b *testing.B) {
			wireAddress := []byte(address)
			b.ReportAllocs()
			for b.Loop() {
				domain, port, ok := parseKnownDomainUDPAddress(wireAddress)
				if !ok {
					b.Fatal("domain address was rejected")
				}
				udpAddressBytesSink = domain
				udpPortSink = port
			}
		})
	}
}

func TestUDPWriterManagedIPv4RoundTrip(t *testing.T) {
	var wire bytes.Buffer
	writer := &UDPWriter{writer: &wire, addr: "fallback.example:443"}
	packet := buf.New()
	if _, err := packet.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	packet.SetManagedUDPIPv4([4]byte{192, 0, 2, 1}, 53)
	if err := writer.WriteMultiBuffer(packet.SingleMultiBuffer()); err != nil {
		t.Fatal(err)
	}
	message, err := ParseUDPMessage(wire.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if message.Addr != "192.0.2.1:53" || string(message.Data) != "payload" {
		t.Fatalf("message = address %q payload %q", message.Addr, message.Data)
	}
}

func TestUDPWriterManagedLongDomainRoundTrip(t *testing.T) {
	domain := string(bytes.Repeat([]byte{'a'}, 64))
	destination := net.UDPDestination(net.DomainAddress(domain), 5353)
	var wire bytes.Buffer
	writer := &UDPWriter{writer: &wire, addr: "fallback.example:443"}
	packet := buf.New()
	if _, err := packet.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	packet.SetManagedUDPDestination(destination)
	if err := writer.WriteMultiBuffer(packet.SingleMultiBuffer()); err != nil {
		t.Fatal(err)
	}
	message, err := ParseUDPMessage(wire.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if message.Addr != destination.NetAddr() || string(message.Data) != "payload" {
		t.Fatalf("message = address %q payload %q", message.Addr, message.Data)
	}
}

type datagramTooLargeOnceWriter struct {
	writes int
}

type fragmentingBenchmarkWriter struct {
	err quic.DatagramTooLargeError
}

func (w *fragmentingBenchmarkWriter) Write(payload []byte) (int, error) {
	if len(payload) > 400 && len(payload) > 8 && payload[7] <= 1 {
		return 0, &w.err
	}
	return len(payload), nil
}

type recordingDatagramWriter struct {
	messages [][]byte
}

func (w *recordingDatagramWriter) Write(payload []byte) (int, error) {
	w.messages = append(w.messages, bytes.Clone(payload))
	return len(payload), nil
}

func TestUDPWriterDefaultHeaderCacheInvalidation(t *testing.T) {
	recorder := new(recordingDatagramWriter)
	writer := &UDPWriter{writer: recorder, addr: "example.com:443"}
	write := func(payload string, managed bool) {
		packet := buf.New()
		if _, err := packet.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		if managed {
			packet.SetManagedUDPIPv4([4]byte{192, 0, 2, 1}, 53)
		}
		if err := writer.WriteMultiBuffer(packet.SingleMultiBuffer()); err != nil {
			t.Fatal(err)
		}
	}
	write("first", false)
	write("managed", true)
	write("second", false)
	for index, want := range []struct {
		address string
		payload string
	}{
		{address: "example.com:443", payload: "first"},
		{address: "192.0.2.1:53", payload: "managed"},
		{address: "example.com:443", payload: "second"},
	} {
		message, err := ParseUDPMessage(recorder.messages[index])
		if err != nil {
			t.Fatal(err)
		}
		if message.Addr != want.address || string(message.Data) != want.payload {
			t.Fatalf("message %d = %q, %q; want %q, %q", index, message.Addr, message.Data, want.address, want.payload)
		}
	}
}

func (w *datagramTooLargeOnceWriter) Write(payload []byte) (int, error) {
	if w.writes == 0 {
		w.writes++
		return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 400}
	}
	w.writes++
	return len(payload), nil
}

func TestUDPWriterFragmentsDatagramTooLarge(t *testing.T) {
	underlying := new(datagramTooLargeOnceWriter)
	writer := &UDPWriter{writer: underlying, addr: "192.0.2.1:53"}
	packet := buf.New()
	if _, err := packet.Write(make([]byte, 1100)); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteMultiBuffer(packet.SingleMultiBuffer()); err != nil {
		t.Fatal(err)
	}
	if underlying.writes < 3 {
		t.Fatalf("writes = %d, want initial failure and multiple fragments", underlying.writes)
	}
}

func TestNewUDPPacketIDIsNeverZero(t *testing.T) {
	for range 10000 {
		if id := newUDPPacketID(); id == 0 {
			t.Fatal("newUDPPacketID returned zero")
		}
	}
}

func TestWrappedDatagramTooLargeErrorFallback(t *testing.T) {
	want := &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1200}
	if got := wrappedDatagramTooLargeError(fmt.Errorf("wrapped: %w", want)); got != want {
		t.Fatalf("wrappedDatagramTooLargeError() = %v, want %v", got, want)
	}
}

func TestUDPWriterRejectsMoreThan255Fragments(t *testing.T) {
	writer := &UDPWriter{writer: io.Discard}
	message := &UDPMessage{Addr: "a:1", Data: make([]byte, 256)}
	if err := writer.sendFragments(message, message.HeaderSize()+1); err == nil {
		t.Fatal("more than 255 fragments were accepted")
	}
}

func BenchmarkUDPWriterWriteMultiBuffer(b *testing.B) {
	payload := make([]byte, 1100)
	writer := &UDPWriter{writer: io.Discard, addr: "fallback.example:443"}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		packet := buf.New()
		if _, err := packet.Write(payload); err != nil {
			b.Fatal(err)
		}
		packet.SetManagedUDPIPv4([4]byte{192, 0, 2, 1}, 53)
		if err := writer.WriteMultiBuffer(packet.SingleMultiBuffer()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUDPWriterManagedDomain(b *testing.B) {
	payload := make([]byte, 1100)
	writer := &UDPWriter{writer: io.Discard, addr: "fallback.example:443"}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		packet := buf.New()
		if _, err := packet.Write(payload); err != nil {
			b.Fatal(err)
		}
		packet.SetManagedUDPDomain("example.com", 443)
		if err := writer.WriteMultiBuffer(packet.SingleMultiBuffer()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUDPWriterFragmented(b *testing.B) {
	payload := make([]byte, 1100)
	underlying := &fragmentingBenchmarkWriter{err: quic.DatagramTooLargeError{MaxDatagramPayloadSize: 400}}
	writer := &UDPWriter{writer: underlying, addr: "192.0.2.1:53"}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		packet := buf.New()
		if _, err := packet.Write(payload); err != nil {
			b.Fatal(err)
		}
		if err := writer.WriteMultiBuffer(packet.SingleMultiBuffer()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUDPWriterDefaultAddress(b *testing.B) {
	payload := make([]byte, 1100)
	writer := &UDPWriter{writer: io.Discard, addr: "192.0.2.1:53"}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		packet := buf.New()
		if _, err := packet.Write(payload); err != nil {
			b.Fatal(err)
		}
		if err := writer.WriteMultiBuffer(packet.SingleMultiBuffer()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUDPWriterDefaultHeaderCache(b *testing.B) {
	payload := make([]byte, 1100)
	b.Run("serialize-each-time", func(b *testing.B) {
		writer := &UDPWriter{writer: io.Discard, addr: "192.0.2.1:53"}
		message := &UDPMessage{FragCount: 1, Addr: writer.addr, Data: payload}
		b.ReportAllocs()
		for b.Loop() {
			if err := writer.sendMessage(message, nil); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("cached", func(b *testing.B) {
		writer := &UDPWriter{writer: io.Discard, addr: "192.0.2.1:53"}
		if err := writer.sendDefaultPayload(payload); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if err := writer.sendDefaultPayload(payload); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestUDPReaderReadFromAllocationBudget(t *testing.T) {
	wire := hysteriaUDPWire("127.0.0.1:443", make([]byte, 1100))
	reader := &UDPReader{reader: repeatedDatagramReader(wire)}
	payload := make([]byte, 2048)
	allocations := testing.AllocsPerRun(1000, func() {
		_, destination, err := reader.ReadFrom(payload)
		if err != nil {
			t.Fatal(err)
		}
		udpDestinationSink = destination
	})
	if allocations > 3 {
		t.Fatalf("UDPReader.ReadFrom allocations = %.0f, want at most 3", allocations)
	}
}

func TestUDPReaderPreservesFragmentDataWithReusableBuffer(t *testing.T) {
	first := hysteriaUDPWire("127.0.0.1:443", []byte("first-"))
	second := hysteriaUDPWire("127.0.0.1:443", []byte("second"))
	binary.BigEndian.PutUint16(first[4:], 7)
	binary.BigEndian.PutUint16(second[4:], 7)
	first[6], first[7] = 0, 2
	second[6], second[7] = 1, 2
	reader := &UDPReader{reader: &sequentialDatagramReader{messages: [][]byte{first, second}}}
	payload := make([]byte, 64)
	n, _, err := reader.ReadFrom(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(payload[:n]), "first-second"; got != want {
		t.Fatalf("defragmented payload = %q, want %q", got, want)
	}
}

func TestUDPReaderReadMultiBufferPreservesFragmentData(t *testing.T) {
	first := hysteriaUDPWire("127.0.0.1:443", []byte("first-"))
	second := hysteriaUDPWire("127.0.0.1:443", []byte("second"))
	binary.BigEndian.PutUint16(first[4:], 9)
	binary.BigEndian.PutUint16(second[4:], 9)
	first[6], first[7] = 0, 2
	second[6], second[7] = 1, 2
	reader := &UDPReader{reader: &sequentialDatagramReader{messages: [][]byte{first, second}}}
	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(mb)
	if len(mb) != 1 || string(mb[0].Bytes()) != "first-second" {
		t.Fatalf("multi buffer payload = %q", mb[0].Bytes())
	}
	if mb[0].UDP == nil || mb[0].UDP.NetAddr() != "127.0.0.1:443" {
		t.Fatalf("multi buffer destination = %v", mb[0].UDP)
	}
}

func TestUDPReaderRejectsOversizedDefragmentedPayloadWithoutPanic(t *testing.T) {
	messages := make([][]byte, 9)
	for index := range messages {
		messages[index] = hysteriaUDPWire("127.0.0.1:443", make([]byte, 1000))
		binary.BigEndian.PutUint16(messages[index][4:], 11)
		messages[index][6] = byte(index)
		messages[index][7] = byte(len(messages))
	}
	reader := &UDPReader{reader: &sequentialDatagramReader{messages: messages}}
	if _, err := reader.ReadMultiBuffer(); !stderrors.Is(err, buf.ErrBufferFull) {
		t.Fatalf("oversized defragmented payload error = %v, want %v", err, buf.ErrBufferFull)
	}
}

func TestUDPReaderDomainRoutingDestinationOutlivesPacketMetadata(t *testing.T) {
	reader := &UDPReader{reader: repeatedDatagramReader(hysteriaUDPWire("example.com:443", []byte("payload")))}
	packet, packetDestination, err := reader.readBufferPacket()
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Release()
	routingDestination := packetDestination.Destination()
	packet.SetManagedUDPDomain("reused.example", 53)
	if got := routingDestination.NetAddr(); got != "example.com:443" {
		t.Fatalf("routing destination changed with packet slab: %q", got)
	}
}

func TestParseUDPDestinationBytes(t *testing.T) {
	for _, test := range []struct {
		input   string
		address string
		port    net.Port
	}{
		{input: "127.0.0.1:53", address: "127.0.0.1", port: 53},
		{input: "[2001:db8::1]:443", address: "[2001:db8::1]", port: 443},
		{input: "example.com:5353", address: "example.com", port: 5353},
	} {
		t.Run(test.input, func(t *testing.T) {
			input := []byte(test.input)
			destination, err := parseUDPDestinationBytes(input)
			if err != nil {
				t.Fatal(err)
			}
			for index := range input {
				input[index] = 'x'
			}
			if got := destination.Address.String(); got != test.address {
				t.Fatalf("address = %q, want %q", got, test.address)
			}
			if destination.Port != test.port {
				t.Fatalf("port = %d, want %d", destination.Port, test.port)
			}
		})
	}
}

func BenchmarkReadTCPRequest(b *testing.B) {
	wire := append([]byte{15}, []byte("example.com:443")...)
	wire = append(wire, 0)
	reader := bytes.NewReader(wire)
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		reader.Reset(wire)
		address, err := ReadTCPRequest(reader)
		if err != nil {
			b.Fatal(err)
		}
		tcpAddressSink = address
	}
}

func BenchmarkReadTCPRequestPadded(b *testing.B) {
	address := "example.com:443"
	wire := make([]byte, 1+len(address)+2+256)
	wire[0] = byte(len(address))
	copy(wire[1:], address)
	varintPut(wire[1+len(address):], 256)
	reader := bytes.NewReader(wire)
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		reader.Reset(wire)
		parsedAddress, err := ReadTCPRequest(reader)
		if err != nil {
			b.Fatal(err)
		}
		tcpAddressSink = parsedAddress
	}
}

func BenchmarkParseServerTCPDestination(b *testing.B) {
	address := "example.com:443"
	b.ReportAllocs()
	for b.Loop() {
		destination, err := parseServerTCPDestination(address)
		if err != nil {
			b.Fatal(err)
		}
		tcpDestinationSink = destination
	}
}

func BenchmarkReadServerTCPRequestDestination(b *testing.B) {
	wire := append([]byte{15}, []byte("example.com:443")...)
	wire = append(wire, 0)
	reader := bytes.NewReader(wire)
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		reader.Reset(wire)
		request, err := readServerTCPRequest(reader)
		if err != nil {
			b.Fatal(err)
		}
		tcpDestinationSink = request.destination
		releaseServerTCPRequest(request)
	}
}

func BenchmarkReadServerTCPRequestDestinationPadded(b *testing.B) {
	address := "example.com:443"
	wire := make([]byte, 1+len(address)+2+256)
	wire[0] = byte(len(address))
	copy(wire[1:], address)
	varintPut(wire[1+len(address):], 256)
	reader := bytes.NewReader(wire)
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		reader.Reset(wire)
		request, err := readServerTCPRequest(reader)
		if err != nil {
			b.Fatal(err)
		}
		tcpDestinationSink = request.destination
		releaseServerTCPRequest(request)
	}
}

func BenchmarkWriteTCPResponse(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if err := WriteTCPResponse(io.Discard, true, ""); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriteTCPResponseOK(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if err := writeTCPResponseOK(io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}
