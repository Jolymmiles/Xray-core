package mtproxy

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type recordingMiddleWriter struct {
	mu       sync.Mutex
	messages [][]byte
}

func (w *recordingMiddleWriter) write(message []byte) error {
	w.mu.Lock()
	w.messages = append(w.messages, append([]byte(nil), message...))
	w.mu.Unlock()
	return nil
}

func (w *recordingMiddleWriter) snapshot() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	result := make([][]byte, len(w.messages))
	for i := range w.messages {
		result[i] = append([]byte(nil), w.messages[i]...)
	}
	return result
}

func TestMiddlePoolMultiplexesAnswersAndAcknowledgements(t *testing.T) {
	writer := new(recordingMiddleWriter)
	session, err := NewMiddleSession(4, 2, writer.write)
	if err != nil {
		t.Fatal(err)
	}
	first, err := session.OpenClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := session.OpenClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID() == second.ID() || first.ID() == 0 {
		t.Fatalf("client IDs = %d / %d", first.ID(), second.ID())
	}

	if err := first.Send(ProxyRequest{Payload: []byte{1, 2, 3, 4}}); err != nil {
		t.Fatal(err)
	}
	if err := second.Send(ProxyRequest{Payload: []byte{5, 6, 7, 8}}); err != nil {
		t.Fatal(err)
	}
	messages := writer.snapshot()
	if len(messages) != 2 {
		t.Fatalf("written messages = %d, want 2", len(messages))
	}
	decodedFirst, _ := DecodeProxyRequest(messages[0], 1024)
	decodedSecond, _ := DecodeProxyRequest(messages[1], 1024)
	if decodedFirst.ConnectionID != first.ID() || decodedSecond.ConnectionID != second.ID() {
		t.Fatalf("written IDs = %d / %d", decodedFirst.ConnectionID, decodedSecond.ConnectionID)
	}

	if err := session.HandleMessage(EncodeProxyAnswer(ProxyAnswer{ConnectionID: second.ID(), Payload: []byte{9, 8, 7, 6}}), 1024); err != nil {
		t.Fatal(err)
	}
	if err := session.HandleMessage(EncodeSimpleAck(SimpleAck{ConnectionID: first.ID(), Confirm: 0xaabbccdd}), 1024); err != nil {
		t.Fatal(err)
	}
	delivery := receiveMiddleDelivery(t, second)
	if !bytes.Equal(delivery.Payload, []byte{9, 8, 7, 6}) {
		t.Fatalf("second payload = %v", delivery.Payload)
	}
	delivery = receiveMiddleDelivery(t, first)
	if delivery.Confirm != 0xaabbccdd || delivery.Kind != MiddleDeliveryAck {
		t.Fatalf("first delivery = %+v", delivery)
	}
}

func TestMiddlePoolBackpressureClosesOnlySlowClient(t *testing.T) {
	session, _ := NewMiddleSession(4, 1, func([]byte) error { return nil })
	var firstClosed, secondClosed atomic.Int32
	first, _ := session.OpenClient(func() { firstClosed.Add(1) })
	second, _ := session.OpenClient(func() { secondClosed.Add(1) })

	answer := func(id uint64, value byte) []byte {
		return EncodeProxyAnswer(ProxyAnswer{ConnectionID: id, Payload: []byte{value, 0, 0, 0}})
	}
	if err := session.HandleMessage(answer(first.ID(), 1), 1024); err != nil {
		t.Fatal(err)
	}
	if err := session.HandleMessage(answer(first.ID(), 2), 1024); !errors.Is(err, ErrMiddleBackpressure) {
		t.Fatalf("overflow error = %v, want ErrMiddleBackpressure", err)
	}
	if firstClosed.Load() != 1 || secondClosed.Load() != 0 {
		t.Fatalf("close counts = %d / %d", firstClosed.Load(), secondClosed.Load())
	}
	if err := second.Send(ProxyRequest{Payload: []byte{1, 2, 3, 4}}); err != nil {
		t.Fatalf("second Send() after first overflow = %v", err)
	}
}

func TestMiddlePoolSelectsLeastLoadedSessionAndDefaultDC(t *testing.T) {
	first, _ := NewMiddleSession(2, 1, func([]byte) error { return nil })
	second, _ := NewMiddleSession(2, 1, func([]byte) error { return nil })
	fallback, _ := NewMiddleSession(2, 1, func([]byte) error { return nil })
	pool, err := NewMiddlePool(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.AddSession(2, first); err != nil {
		t.Fatal(err)
	}
	if err := pool.AddSession(2, second); err != nil {
		t.Fatal(err)
	}
	if err := pool.AddSession(1, fallback); err != nil {
		t.Fatal(err)
	}
	if err := pool.AddSession(2, fallback); !errors.Is(err, ErrMiddleCapacity) {
		t.Fatalf("third session error = %v, want ErrMiddleCapacity", err)
	}

	client1, err := pool.OpenClient(2, nil)
	if err != nil {
		t.Fatal(err)
	}
	client2, err := pool.OpenClient(2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if client1.session == client2.session {
		t.Fatal("least-loaded selection reused a loaded session")
	}
	unknownDC, err := pool.OpenClient(99, nil)
	if err != nil {
		t.Fatal(err)
	}
	if unknownDC.session != fallback {
		t.Fatal("unknown DC did not use default session")
	}
}

func TestMiddlePoolExactDoesNotUseDefaultDCSession(t *testing.T) {
	defaultSession, _ := NewMiddleSession(2, 1, func([]byte) error { return nil })
	pool, _ := NewMiddlePool(2, 2)
	if err := pool.AddSession(2, defaultSession); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.OpenClientExact(4, nil); !errors.Is(err, ErrMiddleClosed) {
		t.Fatalf("OpenClientExact(4) error = %v, want ErrMiddleClosed", err)
	}
	client, err := pool.OpenClient(4, nil)
	if err != nil || client.session != defaultSession {
		t.Fatalf("fallback OpenClient(4) = %+v, %v", client, err)
	}
}

func TestMiddlePoolDeliveryByteBudgetIsReleasedOnReceive(t *testing.T) {
	session, err := newMiddleSession(2, 8, 24, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	client, _ := session.OpenClient(nil)
	answer := EncodeProxyAnswer(ProxyAnswer{ConnectionID: client.ID(), Payload: []byte{1, 2, 3, 4}})
	if err := session.HandleMessage(answer, 1024); err != nil {
		t.Fatal(err)
	}
	if _, ok := client.Receive(); !ok {
		t.Fatal("Receive() returned closed")
	}
	if err := session.HandleMessage(answer, 1024); err != nil {
		t.Fatalf("budget was not released after Receive: %v", err)
	}
}

func TestMiddlePoolDeliveryByteBudgetClosesOnlyOverflowingClient(t *testing.T) {
	session, _ := newMiddleSession(2, 8, 20, func([]byte) error { return nil })
	var firstClosed, secondClosed atomic.Int32
	first, _ := session.OpenClient(func() { firstClosed.Add(1) })
	second, _ := session.OpenClient(func() { secondClosed.Add(1) })
	answer := func(id uint64) []byte {
		return EncodeProxyAnswer(ProxyAnswer{ConnectionID: id, Payload: []byte{1, 2, 3, 4}})
	}
	if err := session.HandleMessage(answer(first.ID()), 1024); err != nil {
		t.Fatal(err)
	}
	if err := session.HandleMessage(answer(second.ID()), 1024); !errors.Is(err, ErrMiddleBackpressure) {
		t.Fatalf("session byte overflow error = %v", err)
	}
	if firstClosed.Load() != 0 || secondClosed.Load() != 1 {
		t.Fatalf("close counts = %d / %d", firstClosed.Load(), secondClosed.Load())
	}
	if _, ok := first.Receive(); !ok {
		t.Fatal("first client was closed by second client overflow")
	}
}

func TestMiddleClientRevokeWaitsForInFlightRequestWrite(t *testing.T) {
	writeStarted := make(chan struct{}, 2)
	releaseWrite := make(chan struct{})
	var writes atomic.Int32
	session, _ := NewMiddleSession(1, 1, func([]byte) error {
		writes.Add(1)
		writeStarted <- struct{}{}
		<-releaseWrite
		return nil
	})
	client, _ := session.OpenClient(nil)
	sendDone := make(chan error, 1)
	go func() { sendDone <- client.Send(ProxyRequest{Payload: []byte{1, 2, 3, 4}}) }()
	<-writeStarted
	revokeDone := make(chan struct{})
	go func() { client.Revoke(); close(revokeDone) }()
	select {
	case <-revokeDone:
		t.Fatal("Revoke returned while request write was in flight")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseWrite)
	if err := <-sendDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-revokeDone:
	case <-time.After(time.Second):
		t.Fatal("Revoke did not finish after write completion")
	}
	if err := client.Send(ProxyRequest{Payload: []byte{5, 6, 7, 8}}); !errors.Is(err, ErrMiddleClosed) {
		t.Fatalf("post-revoke Send error = %v", err)
	}
	if writes.Load() != 2 { // request plus logical close notification
		t.Fatalf("writes = %d, want request plus close only", writes.Load())
	}
}

func TestMiddlePoolCapacityCloseAndFailure(t *testing.T) {
	writer := new(recordingMiddleWriter)
	session, _ := NewMiddleSession(1, 1, writer.write)
	var closed atomic.Int32
	client, _ := session.OpenClient(func() { closed.Add(1) })
	if _, err := session.OpenClient(nil); !errors.Is(err, ErrMiddleCapacity) {
		t.Fatalf("OpenClient over capacity error = %v", err)
	}

	client.Close()
	client.Close()
	if closed.Load() != 1 {
		t.Fatalf("close callback count = %d, want 1", closed.Load())
	}
	messages := writer.snapshot()
	if len(messages) != 1 {
		t.Fatalf("close messages = %d, want 1", len(messages))
	}
	decoded, err := DecodeMiddleMessage(messages[0], 1024)
	if err != nil {
		t.Fatal(err)
	}
	if closeMessage, ok := decoded.(CloseConnection); !ok || closeMessage.ConnectionID != client.ID() {
		t.Fatalf("close message = %#v", decoded)
	}

	replacement, err := session.OpenClient(func() { closed.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	session.Fail(errors.New("backend failed"))
	if closed.Load() != 2 {
		t.Fatalf("close count after failure = %d, want 2", closed.Load())
	}
	if _, ok := replacement.Receive(); ok {
		t.Fatal("delivery channel remains open after failure")
	}
	if _, err := session.OpenClient(nil); !errors.Is(err, ErrMiddleClosed) {
		t.Fatalf("OpenClient after failure error = %v", err)
	}
}

func TestMiddleClientConsumedDeliveriesDoNotExhaustBudget(t *testing.T) {
	session, err := newMiddleSession(1, 1, 24, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer session.Fail(ErrMiddleClosed)
	client, err := session.OpenClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 4 {
		if err := session.HandleMessage(EncodeProxyAnswer(ProxyAnswer{ConnectionID: client.ID(), Payload: []byte{1, 2, 3, 4}}), 4); err != nil {
			t.Fatal(err)
		}
		delivery := receiveMiddleDelivery(t, client)
		if !bytes.Equal(delivery.Payload, []byte{1, 2, 3, 4}) {
			t.Fatal("delivery payload changed")
		}
	}
}

func receiveMiddleDelivery(t *testing.T, client *MiddleClient) MiddleDelivery {
	t.Helper()
	t.Cleanup(client.Close)
	received := make(chan MiddleDelivery, 1)
	go func() { delivery, _ := client.Receive(); received <- delivery }()
	select {
	case delivery := <-received:
		return delivery
	case <-time.After(time.Second):
		t.Fatal("Middle-End delivery did not arrive")
		return MiddleDelivery{}
	}
}
