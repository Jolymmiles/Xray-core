package encoding_test

import (
	"bytes"
	"encoding/hex"
	"io"
	"strconv"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
	. "github.com/xtls/xray-core/proxy/vless/encoding"
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
