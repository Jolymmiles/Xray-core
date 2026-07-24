package encoding_test

import (
	"bytes"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	. "github.com/xtls/xray-core/proxy/vless/encoding"
)

var (
	trafficStateBenchmarkSink *proxy.TrafficState
	behaviorStringSink        string
	behaviorReaderSink        buf.Reader
	behaviorWriterSink        buf.Writer
	behaviorFlow              string
)

const (
	behaviorUserID       = "00112233-4455-6677-8899-aabbccddeeff"
	requestTCPDomainWire = "0000112233445566778899aabbccddeeff000101bb020b6578616d706c652e636f6d"
	requestTCPIPv4Wire   = "0000112233445566778899aabbccddeeff000101bb01c0000201"
	requestTCPIPv6Wire   = "0000112233445566778899aabbccddeeff000101bb0320010db8000000000000000000000001"
	requestMuxWire       = "0000112233445566778899aabbccddeeff0003"
	responseWire         = "0000"
)

func behaviorUser(t testing.TB) *protocol.MemoryUser {
	t.Helper()
	id, err := uuid.ParseString(behaviorUserID)
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.MemoryUser{
		Level:   0,
		Email:   "baseline@example.com",
		Account: toAccount(&vless.Account{Id: id.String()}),
	}
}

func behaviorRequest(t testing.TB, command protocol.RequestCommand) *protocol.RequestHeader {
	t.Helper()
	request := &protocol.RequestHeader{
		Version: Version,
		User:    behaviorUser(t),
		Command: command,
	}
	if command == protocol.RequestCommandMux {
		request.Address = net.DomainAddress("v1.mux.cool")
		return request
	}
	request.Address = net.DomainAddress("example.com")
	request.Port = 443
	return request
}

func decodeWire(t testing.TB, wire string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(wire)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestRequestWireFormat(t *testing.T) {
	for _, test := range []struct {
		name    string
		command protocol.RequestCommand
		address net.Address
		wire    string
	}{
		{name: "tcp-domain", command: protocol.RequestCommandTCP, address: net.DomainAddress("example.com"), wire: requestTCPDomainWire},
		{name: "tcp-ipv4", command: protocol.RequestCommandTCP, address: net.IPAddress([]byte{192, 0, 2, 1}), wire: requestTCPIPv4Wire},
		{name: "tcp-ipv6", command: protocol.RequestCommandTCP, address: net.IPAddress([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), wire: requestTCPIPv6Wire},
		{name: "mux", command: protocol.RequestCommandMux, wire: requestMuxWire},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := behaviorRequest(t, test.command)
			if test.address != nil {
				request.Address = test.address
			}
			buffer := buf.StackNew()
			defer buffer.Release()
			if err := EncodeRequestHeader(&buffer, request, &Addons{}); err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(buffer.Bytes()); got != test.wire {
				t.Fatalf("wire = %s, want %s", got, test.wire)
			}
		})
	}
}

func TestResponseWireFormat(t *testing.T) {
	buffer := buf.StackNew()
	defer buffer.Release()
	if err := EncodeResponseHeader(&buffer, behaviorRequest(t, protocol.RequestCommandTCP), &Addons{}); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(buffer.Bytes()); got != responseWire {
		t.Fatalf("wire = %s, want %s", got, responseWire)
	}
}

func TestDecodeRequestHeaderPreservesCoalescedPayload(t *testing.T) {
	user := behaviorUser(t)
	validator := new(vless.MemoryValidator)
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}
	payload := []byte("coalesced-first-payload")
	first := buf.FromBytes(append(decodeWire(t, requestTCPDomainWire), payload...))
	reader := &buf.BufferedReader{
		Reader: buf.NewReader(bytes.NewReader(nil)),
		Buffer: buf.MultiBuffer{first},
	}

	userID, request, addons, fallback, err := DecodeRequestHeader(true, first, reader, validator)
	if err != nil {
		t.Fatal(err)
	}
	if fallback {
		t.Fatal("valid first buffer was classified as fallback")
	}
	if got := hex.EncodeToString(userID); got != "00112233445566778899aabbccddeeff" {
		t.Fatalf("user id = %s", got)
	}
	if request.Command != protocol.RequestCommandTCP || request.Address.String() != "example.com" || request.Port != 443 {
		t.Fatalf("decoded request = %+v", request)
	}
	if addons.Flow != "" || len(addons.Seed) != 0 {
		t.Fatalf("decoded addons = %+v", addons)
	}
	remaining, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(remaining, payload) {
		t.Fatalf("remaining payload = %q, want %q", remaining, payload)
	}
}

func TestDecodeRequestHeaderFragmentedFirstBuffer(t *testing.T) {
	user := behaviorUser(t)
	validator := new(vless.MemoryValidator)
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}
	payload := []byte("fragmented-first-payload")

	for _, test := range []struct {
		name string
		wire string
	}{
		{name: "domain", wire: requestTCPDomainWire},
		{name: "ipv4", wire: requestTCPIPv4Wire},
		{name: "ipv6", wire: requestTCPIPv6Wire},
		{name: "mux", wire: requestMuxWire},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := decodeWire(t, test.wire)
			for split := 18; split < len(wire); split++ {
				t.Run(strconv.Itoa(split), func(t *testing.T) {
					first := buf.FromBytes(wire[:split])
					remaining := make([]byte, 0, len(wire)-split+len(payload))
					remaining = append(remaining, wire[split:]...)
					remaining = append(remaining, payload...)
					reader := &buf.BufferedReader{
						Reader: buf.NewReader(bytes.NewReader(remaining)),
						Buffer: buf.MultiBuffer{first},
					}

					_, _, _, fallback, err := DecodeRequestHeader(true, first, reader, validator)
					if err != nil {
						t.Fatal(err)
					}
					if fallback {
						t.Fatal("valid fragmented request was classified as fallback")
					}
					got, err := io.ReadAll(reader)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, payload) {
						t.Fatalf("remaining payload = %q, want %q", got, payload)
					}
				})
			}
		})
	}
}

func TestDecodeRequestHeaderFromFirstWithoutFallback(t *testing.T) {
	user := behaviorUser(t)
	validator := new(vless.MemoryValidator)
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}

	validWire := decodeWire(t, requestTCPDomainWire)
	first := buf.FromBytes(validWire)
	reader := &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(nil)), Buffer: buf.MultiBuffer{first}}
	sentID, request, _, fallback, err := DecodeRequestHeaderFromFirst(first, reader, validator, false)
	if err != nil {
		t.Fatal(err)
	}
	if fallback || request.Address.String() != "example.com" || request.Port != 443 {
		t.Fatalf("request = %+v, fallback = %v", request, fallback)
	}
	if got := hex.EncodeToString(sentID[:]); got != "00112233445566778899aabbccddeeff" {
		t.Fatalf("sent UUID = %s", got)
	}

	invalidWire := bytes.Clone(validWire)
	invalidWire[1] ^= 0xff
	first = buf.FromBytes(invalidWire)
	reader = &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(nil)), Buffer: buf.MultiBuffer{first}}
	_, _, _, fallback, err = DecodeRequestHeaderFromFirst(first, reader, validator, false)
	if err == nil {
		t.Fatal("invalid user ID was accepted")
	}
	if fallback {
		t.Fatal("no-fallback decode classified invalid user ID as fallback")
	}
}

func TestDecodeRequestHeaderRejectsEmptyDomainWithoutPanic(t *testing.T) {
	user := behaviorUser(t)
	validator := new(vless.MemoryValidator)
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}
	wire := decodeWire(t, "0000112233445566778899aabbccddeeff000101bb0200")
	first := buf.FromBytes(wire[:17])
	defer first.Release()
	reader := bytes.NewReader(wire[17:])
	if _, request, _, _, err := DecodeRequestHeaderFromFirst(first, reader, validator, false); err == nil || request != nil {
		t.Fatalf("empty domain decoded as request %+v with error %v", request, err)
	}
}

func TestDecodeRequestHeaderIPv4DoesNotAliasFirstBuffer(t *testing.T) {
	user := behaviorUser(t)
	validator := new(vless.MemoryValidator)
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}
	first := buf.FromBytes(decodeWire(t, requestTCPIPv4Wire))
	storage := first.Bytes()
	reader := &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(nil)), Buffer: buf.MultiBuffer{first}}
	_, request, _, _, err := DecodeRequestHeaderFromFirst(first, reader, validator, false)
	if err != nil {
		t.Fatal(err)
	}
	defer ReleaseRequestHeader(request)
	defer first.Release()
	for index := 22; index < 26; index++ {
		storage[index] = 0
	}
	if got := request.Address.String(); got != "192.0.2.1" {
		t.Fatalf("IPv4 address aliases first buffer: %q", got)
	}
}

func TestDecodeRequestHeaderIPv6DoesNotAliasFirstBuffer(t *testing.T) {
	user := behaviorUser(t)
	validator := new(vless.MemoryValidator)
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}
	first := buf.FromBytes(decodeWire(t, requestTCPIPv6Wire))
	storage := first.Bytes()
	reader := bytes.NewReader(nil)
	_, request, _, _, err := DecodeRequestHeaderFromFirst(first, reader, validator, false)
	if err != nil {
		t.Fatal(err)
	}
	defer ReleaseRequestHeader(request)
	defer first.Release()
	for index := 22; index < 38; index++ {
		storage[index] = 0
	}
	if got := request.Address.String(); got != "[2001:db8::1]" {
		t.Fatalf("IPv6 address aliases first buffer: %q", got)
	}
}

func TestDecodeRequestHeaderDomainDoesNotAliasFirstBuffer(t *testing.T) {
	user := behaviorUser(t)
	validator := new(vless.MemoryValidator)
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}
	first := buf.FromBytes(decodeWire(t, requestTCPDomainWire))
	storage := first.Bytes()
	reader := &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(nil)), Buffer: buf.MultiBuffer{first}}
	_, request, _, _, err := DecodeRequestHeaderFromFirst(first, reader, validator, false)
	if err != nil {
		t.Fatal(err)
	}
	defer ReleaseRequestHeader(request)
	for index := 23; index < len(storage); index++ {
		storage[index] = 'x'
	}
	if got := request.Address.String(); got != "example.com" {
		t.Fatalf("domain address aliases first buffer: %q", got)
	}
}

func TestDecodeRequestHeaderPooledDomainBoundaries(t *testing.T) {
	user := behaviorUser(t)
	validator := new(vless.MemoryValidator)
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 64),
		"example.org",
	} {
		request := behaviorRequest(t, protocol.RequestCommandTCP)
		request.Address = net.DomainAddress(domain)
		wire := buf.StackNew()
		if err := EncodeRequestHeader(&wire, request, &Addons{}); err != nil {
			wire.Release()
			t.Fatal(err)
		}
		first := buf.FromBytes(append([]byte(nil), wire.Bytes()...))
		wire.Release()
		storage := first.Bytes()
		reader := bytes.NewReader(nil)
		_, decoded, _, _, err := DecodeRequestHeaderFromFirst(first, reader, validator, false)
		if err != nil {
			first.Release()
			t.Fatal(err)
		}
		for index := 23; index < len(storage); index++ {
			storage[index] = 'x'
		}
		if got := decoded.Address.Domain(); got != domain {
			t.Fatalf("domain length %d aliases input or pool state: %q", len(domain), got)
		}
		ReleaseRequestHeader(decoded)
		first.Release()
	}
}

func TestDecodeRequestHeaderFromFirstAllocationBudget(t *testing.T) {
	user := behaviorUser(t)
	validator := new(vless.MemoryValidator)
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}
	wire := decodeWire(t, requestTCPDomainWire)
	allocations := testing.AllocsPerRun(1000, func() {
		first := buf.FromBytes(wire)
		reader := &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(nil)), Buffer: buf.MultiBuffer{first}}
		_, request, _, _, err := DecodeRequestHeaderFromFirst(first, reader, validator, false)
		if err != nil {
			t.Fatal(err)
		}
		ReleaseRequestHeader(request)
		reader.Buffer = buf.ReleaseMulti(reader.Buffer)
	})
	if allocations > 6 {
		t.Fatalf("no-fallback first-buffer decode allocations = %.0f, want at most 6", allocations)
	}
}

type behaviorWriter struct{}

func (*behaviorWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}

func TestPlainTCPBodyAddonsArePassThrough(t *testing.T) {
	request := behaviorRequest(t, protocol.RequestCommandTCP)
	writer := new(behaviorWriter)
	if got := EncodeBodyAddons(writer, request, &Addons{}, nil, true, nil, nil, nil); got != writer {
		t.Fatalf("plain TCP writer type = %T, want unchanged writer", got)
	}

	payload := []byte("plain-vless-payload")
	reader := DecodeBodyAddons(bytes.NewReader(payload), request, &Addons{})
	mb, err := reader.ReadMultiBuffer()
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	rest, count := buf.SplitBytes(mb, got)
	buf.ReleaseMulti(rest)
	if count != len(payload) || !bytes.Equal(got, payload) {
		t.Fatalf("decoded body = %q, want %q", got[:count], payload)
	}
}

func TestNewTrafficStateForFlow(t *testing.T) {
	userID := decodeWire(t, "00112233445566778899aabbccddeeff")
	if state := NewTrafficStateForFlow(userID, ""); state != nil {
		t.Fatal("plain VLESS unexpectedly allocated Vision traffic state")
	}

	state := NewTrafficStateForFlow(userID, vless.XRV)
	if state == nil {
		t.Fatal("Vision traffic state is nil")
	}
	if !bytes.Equal(state.UserUUID, userID) || state.NumberOfPacketToFilter != 8 {
		t.Fatalf("unexpected Vision traffic state: %+v", state)
	}
}

func BenchmarkEncodeRequestHeaderTCPDomain(b *testing.B) {
	request := behaviorRequest(b, protocol.RequestCommandTCP)
	output := buf.StackNew()
	defer output.Release()
	b.ReportAllocs()
	b.SetBytes(int64(len(decodeWire(b, requestTCPDomainWire))))
	for b.Loop() {
		output.Clear()
		if err := EncodeRequestHeader(&output, request, &Addons{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewTrafficStateBaseline(b *testing.B) {
	userID := decodeWire(b, "00112233445566778899aabbccddeeff")
	b.ReportAllocs()
	for b.Loop() {
		trafficStateBenchmarkSink = proxy.NewTrafficState(userID)
	}
}

func BenchmarkNewTrafficStateForFlowPlain(b *testing.B) {
	userID := decodeWire(b, "00112233445566778899aabbccddeeff")
	b.ReportAllocs()
	for b.Loop() {
		trafficStateBenchmarkSink = NewTrafficStateForFlow(userID, "")
	}
}

func BenchmarkNewTrafficStateForFlowVision(b *testing.B) {
	userID := decodeWire(b, "00112233445566778899aabbccddeeff")
	b.ReportAllocs()
	for b.Loop() {
		trafficStateBenchmarkSink = NewTrafficStateForFlow(userID, vless.XRV)
	}
}

func BenchmarkDecodeRequestHeaderTCPDomain(b *testing.B) {
	user := behaviorUser(b)
	validator := new(vless.MemoryValidator)
	if err := validator.Add(user); err != nil {
		b.Fatal(err)
	}
	wire := decodeWire(b, requestTCPDomainWire)
	var reader bytes.Reader
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		reader.Reset(wire)
		if _, _, _, _, err := DecodeRequestHeader(false, nil, &reader, validator); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeRequestHeaderInvalidUser(b *testing.B) {
	wire := decodeWire(b, requestTCPDomainWire)
	validator := new(vless.MemoryValidator)
	var reader bytes.Reader
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		reader.Reset(wire)
		if _, request, _, _, err := DecodeRequestHeader(false, nil, &reader, validator); err == nil || request != nil {
			b.Fatalf("DecodeRequestHeader = (request=%v, err=%v), want nil request and error", request, err)
		}
	}
}

func BenchmarkDecodeRequestHeaderInvalidUserErrorString(b *testing.B) {
	wire := decodeWire(b, requestTCPDomainWire)
	validator := new(vless.MemoryValidator)
	var reader bytes.Reader
	b.ReportAllocs()
	for b.Loop() {
		reader.Reset(wire)
		_, _, _, _, err := DecodeRequestHeader(false, nil, &reader, validator)
		if err == nil {
			b.Fatal("DecodeRequestHeader unexpectedly succeeded")
		}
		behaviorStringSink = err.Error()
	}
}

func BenchmarkDecodeRequestHeaderTCPDomainFirstBuffer(b *testing.B) {
	user := behaviorUser(b)
	validator := new(vless.MemoryValidator)
	if err := validator.Add(user); err != nil {
		b.Fatal(err)
	}
	wire := decodeWire(b, requestTCPDomainWire)
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		first := buf.FromBytes(wire)
		reader := &buf.BufferedReader{
			Reader: buf.NewReader(bytes.NewReader(nil)),
			Buffer: buf.MultiBuffer{first},
		}
		if _, _, _, _, err := DecodeRequestHeader(true, first, reader, validator); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeRequestHeaderTCPDomainReusableFirstBuffer(b *testing.B) {
	benchmarkDecodeRequestHeaderReusableFirstBuffer(b, requestTCPDomainWire)
}

func BenchmarkDecodeRequestHeaderTCPIPv4ReusableFirstBuffer(b *testing.B) {
	benchmarkDecodeRequestHeaderReusableFirstBuffer(b, requestTCPIPv4Wire)
}

func BenchmarkDecodeRequestHeaderTCPIPv6ReusableFirstBuffer(b *testing.B) {
	benchmarkDecodeRequestHeaderReusableFirstBuffer(b, requestTCPIPv6Wire)
}

func BenchmarkDecodeRequestHeaderTCPDomainFragmentedFirstBuffer(b *testing.B) {
	benchmarkDecodeRequestHeaderFragmentedFirstBuffer(b, requestTCPDomainWire)
}

func BenchmarkDecodeRequestHeaderTCPIPv4FragmentedFirstBuffer(b *testing.B) {
	benchmarkDecodeRequestHeaderFragmentedFirstBuffer(b, requestTCPIPv4Wire)
}

func BenchmarkDecodeRequestHeaderTCPIPv6FragmentedFirstBuffer(b *testing.B) {
	benchmarkDecodeRequestHeaderFragmentedFirstBuffer(b, requestTCPIPv6Wire)
}

func BenchmarkDecodeRequestHeaderTCPDomainFragmentedBufferedReader(b *testing.B) {
	user := behaviorUser(b)
	validator := new(vless.MemoryValidator)
	if err := validator.Add(user); err != nil {
		b.Fatal(err)
	}
	wire := decodeWire(b, requestTCPDomainWire)
	first := buf.FromBytes(make([]byte, 17))
	defer first.Release()
	remainder := buf.FromBytes(make([]byte, len(wire)-17))
	defer remainder.Release()
	reader := &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(nil))}
	buffered := make(buf.MultiBuffer, 2)
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		first.Clear()
		_, _ = first.Write(wire[:17])
		remainder.Clear()
		_, _ = remainder.Write(wire[17:])
		buffered[0] = first
		buffered[1] = remainder
		reader.Buffer = buffered
		_, request, _, _, err := DecodeRequestHeaderFromFirst(first, reader, validator, false)
		if err != nil {
			b.Fatal(err)
		}
		ReleaseRequestHeader(request)
		reader.Buffer = nil
	}
}

func benchmarkDecodeRequestHeaderFragmentedFirstBuffer(b *testing.B, encodedWire string) {
	b.Helper()
	user := behaviorUser(b)
	validator := new(vless.MemoryValidator)
	if err := validator.Add(user); err != nil {
		b.Fatal(err)
	}
	wire := decodeWire(b, encodedWire)
	first := buf.New()
	defer first.Release()
	reader := bytes.NewReader(nil)
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		first.Clear()
		_, _ = first.Write(wire[:17])
		reader.Reset(wire[17:])
		_, request, _, _, err := DecodeRequestHeaderFromFirst(first, reader, validator, false)
		if err != nil {
			b.Fatal(err)
		}
		ReleaseRequestHeader(request)
	}
}

func benchmarkDecodeRequestHeaderReusableFirstBuffer(b *testing.B, encodedWire string) {
	b.Helper()
	user := behaviorUser(b)
	validator := new(vless.MemoryValidator)
	if err := validator.Add(user); err != nil {
		b.Fatal(err)
	}
	wire := decodeWire(b, encodedWire)
	first := buf.New()
	defer first.Release()
	reader := bytes.NewReader(nil)
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		first.Clear()
		_, _ = first.Write(wire)
		_, request, _, _, err := DecodeRequestHeaderFromFirst(first, reader, validator, false)
		if err != nil {
			b.Fatal(err)
		}
		ReleaseRequestHeader(request)
	}
}

func BenchmarkDecodeRequestHeaderTCPDomainBufferedNoFallback(b *testing.B) {
	benchmarkDecodeRequestHeaderBufferedNoFallback(b, requestTCPDomainWire)
}

func BenchmarkDecodeRequestHeaderTCPIPv4BufferedNoFallback(b *testing.B) {
	benchmarkDecodeRequestHeaderBufferedNoFallback(b, requestTCPIPv4Wire)
}

func BenchmarkDecodeRequestHeaderTCPIPv6BufferedNoFallback(b *testing.B) {
	benchmarkDecodeRequestHeaderBufferedNoFallback(b, requestTCPIPv6Wire)
}

func benchmarkDecodeRequestHeaderBufferedNoFallback(b *testing.B, encodedWire string) {
	b.Helper()
	user := behaviorUser(b)
	validator := new(vless.MemoryValidator)
	if err := validator.Add(user); err != nil {
		b.Fatal(err)
	}
	wire := decodeWire(b, encodedWire)
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for b.Loop() {
		first := buf.FromBytes(wire)
		reader := &buf.BufferedReader{
			Reader: buf.NewReader(bytes.NewReader(nil)),
			Buffer: buf.MultiBuffer{first},
		}
		_, request, _, _, err := DecodeRequestHeaderFromFirst(first, reader, validator, false)
		if err != nil {
			b.Fatal(err)
		}
		ReleaseRequestHeader(request)
		reader.Buffer = buf.ReleaseMulti(reader.Buffer)
	}
}

func BenchmarkEncodeResponseHeader(b *testing.B) {
	request := behaviorRequest(b, protocol.RequestCommandTCP)
	output := buf.StackNew()
	defer output.Release()
	b.ReportAllocs()
	b.SetBytes(2)
	for b.Loop() {
		output.Clear()
		if err := EncodeResponseHeader(&output, request, &Addons{}); err != nil {
			b.Fatal(err)
		}
	}
}

func TestEncodeResponseHeaderNilAddons(t *testing.T) {
	request := behaviorRequest(t, protocol.RequestCommandTCP)
	var output bytes.Buffer
	if err := EncodeResponseHeader(&output, request, nil); err != nil {
		t.Fatal(err)
	}
	if got := output.Bytes(); !bytes.Equal(got, []byte{Version, 0}) {
		t.Fatalf("response header = %x, want %x", got, []byte{Version, 0})
	}
}

func BenchmarkEncodePlainResponseHeaderNilAddons(b *testing.B) {
	request := behaviorRequest(b, protocol.RequestCommandTCP)
	output := buf.StackNew()
	defer output.Release()
	b.ReportAllocs()
	b.SetBytes(2)
	for b.Loop() {
		output.Clear()
		if err := EncodeResponseHeader(&output, request, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeResponseHeader(b *testing.B) {
	request := behaviorRequest(b, protocol.RequestCommandTCP)
	wire := decodeWire(b, responseWire)
	var reader bytes.Reader
	b.ReportAllocs()
	b.SetBytes(2)
	for b.Loop() {
		reader.Reset(wire)
		if _, err := DecodeResponseHeader(&reader, request); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeBodyAddonsPlainHeader(b *testing.B) {
	request := behaviorRequest(b, protocol.RequestCommandTCP)
	reader := &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(nil))}
	b.ReportAllocs()
	for b.Loop() {
		behaviorReaderSink = DecodeBody(reader, request)
	}
}

func BenchmarkEncodeBodyAddonsPlainHeader(b *testing.B) {
	request := behaviorRequest(b, protocol.RequestCommandTCP)
	writer := new(behaviorWriter)
	addons := HeaderAddons{}
	b.ReportAllocs()
	for b.Loop() {
		behaviorWriterSink = EncodeBodyAddonsFlow(writer, request, addons.Flow, nil, false, nil, nil, nil)
	}
}

func BenchmarkPlainBodyFlowDecision(b *testing.B) {
	request := behaviorRequest(b, protocol.RequestCommandTCP)
	reader := &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(nil))}
	writer := new(behaviorWriter)
	userID := decodeWire(b, "00112233445566778899aabbccddeeff")
	behaviorFlow = ""
	b.ReportAllocs()
	for b.Loop() {
		flow := behaviorFlow
		vision := flow == vless.XRV
		trafficStateBenchmarkSink = NewTrafficStateForVision(userID, vision)
		behaviorReaderSink = DecodeBody(reader, request)
		if vision {
			behaviorStringSink = flow
		}
		behaviorWriterSink = EncodeBody(writer, request, vision, nil, false, nil, nil, nil)
	}
}
