package mtproxy

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"
)

func TestRPCFrameRoundTripAndValidation(t *testing.T) {
	payload := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	frame, err := EncodeMiddleRPCFrame(7, payload)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(frame[:4]); got != uint32(len(payload)+12) {
		t.Fatalf("frame length = %d", got)
	}
	if got := binary.LittleEndian.Uint32(frame[len(frame)-4:]); got != crc32.ChecksumIEEE(frame[:len(frame)-4]) {
		t.Fatalf("frame CRC = %#x", got)
	}

	decoded, err := ReadMiddleRPCFrame(&fragmentReader{data: frame, step: 1}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Sequence != 7 || !bytes.Equal(decoded.Payload, payload) {
		t.Fatalf("decoded = %+v", decoded)
	}

	corrupt := append([]byte(nil), frame...)
	corrupt[len(corrupt)-1] ^= 1
	if _, err := ReadMiddleRPCFrame(bytes.NewReader(corrupt), 1024); err == nil {
		t.Fatal("ReadMiddleRPCFrame() accepted bad CRC")
	}
	if _, err := ReadMiddleRPCFrame(bytes.NewReader(frame), 4); err == nil {
		t.Fatal("ReadMiddleRPCFrame() accepted oversized frame")
	}
}

func TestRPCFrameCRC32CNegotiation(t *testing.T) {
	table := crc32.MakeTable(crc32.Castagnoli)
	payload := []byte{1, 2, 3, 4}
	frame, err := encodeMiddleRPCFrame(0, payload, table)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := binary.LittleEndian.Uint32(frame[len(frame)-4:]), crc32.Checksum(frame[:len(frame)-4], table); got != want {
		t.Fatalf("CRC32C = %#x, want %#x", got, want)
	}
	if _, err := ReadMiddleRPCFrame(bytes.NewReader(frame), 1024); err == nil {
		t.Fatal("IEEE reader accepted negotiated CRC32C frame")
	}
	decoded, err := readMiddleRPCFrame(bytes.NewReader(frame), 1024, table)
	if err != nil || !bytes.Equal(decoded.Payload, payload) {
		t.Fatalf("CRC32C decode = %+v, %v", decoded, err)
	}
}

func TestProxyRequestAndResponseMessages(t *testing.T) {
	request := ProxyRequest{
		Flags:        8,
		ConnectionID: 0x1122334455667788,
		RemoteIP:     [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4},
		RemotePort:   12345,
		LocalIP:      [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 5, 6, 7, 8},
		LocalPort:    443,
		ProxyTag:     &[16]byte{1, 2, 3, 4},
		Payload:      []byte{9, 8, 7, 6},
	}
	encoded, err := EncodeProxyRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeProxyRequest(encoded, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ConnectionID != request.ConnectionID || decoded.RemotePort != request.RemotePort || !bytes.Equal(decoded.Payload, request.Payload) || decoded.ProxyTag == nil || *decoded.ProxyTag != *request.ProxyTag {
		t.Fatalf("decoded request = %+v", decoded)
	}

	answerBytes := EncodeProxyAnswer(ProxyAnswer{Flags: 16, ConnectionID: request.ConnectionID, Payload: []byte{4, 3, 2, 1}})
	message, err := DecodeMiddleMessage(answerBytes, 1024)
	if err != nil {
		t.Fatal(err)
	}
	answer, ok := message.(ProxyAnswer)
	if !ok || answer.ConnectionID != request.ConnectionID || !bytes.Equal(answer.Payload, []byte{4, 3, 2, 1}) {
		t.Fatalf("decoded answer = %#v", message)
	}

	messages := [][]byte{
		EncodeSimpleAck(SimpleAck{ConnectionID: 1, Confirm: 0xaabbccdd}),
		EncodeCloseConnection(CloseConnection{ConnectionID: 2}),
		EncodeCloseExternal(CloseExternal{ConnectionID: 3}),
	}
	for _, data := range messages {
		if _, err := DecodeMiddleMessage(data, 1024); err != nil {
			t.Fatalf("DecodeMiddleMessage(%x) error = %v", data, err)
		}
	}
}

func TestMiddleRPCPingPongControl(t *testing.T) {
	pingBytes := EncodePing(Ping{ID: 0x1122334455667788})
	message, err := DecodeMiddleMessage(pingBytes, 1024)
	if err != nil || message.(Ping).ID != 0x1122334455667788 {
		t.Fatalf("ping decode = %#v, %v", message, err)
	}
	pongBytes := EncodePong(Pong{ID: message.(Ping).ID})
	message, err = DecodeMiddleMessage(pongBytes, 1024)
	if err != nil || message.(Pong).ID != 0x1122334455667788 {
		t.Fatalf("pong decode = %#v, %v", message, err)
	}
}

func TestReadMiddleRPCFrameRejectsTruncation(t *testing.T) {
	frame, _ := EncodeMiddleRPCFrame(1, []byte{1, 2, 3, 4})
	for length := 0; length < len(frame); length++ {
		if _, err := ReadMiddleRPCFrame(bytes.NewReader(frame[:length]), 1024); err == nil {
			t.Fatalf("length %d unexpectedly succeeded", length)
		}
	}
}
