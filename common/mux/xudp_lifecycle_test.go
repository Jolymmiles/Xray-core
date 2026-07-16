package mux

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/pipe"
)

type xudpTestLease struct {
	active *int
}

func (l *xudpTestLease) Close() { (*l.active)-- }

func TestXUDPStaleDetachCannotExpireCurrentAttachment(t *testing.T) {
	runtime := NewRuntime()
	t.Cleanup(func() { _ = runtime.Close() })
	key := xudpKey{GlobalID: [8]byte{1}}
	flow := &XUDP{GlobalID: key.GlobalID, Status: Active, Generation: 2}
	active := 2
	old := &Session{XUDP: flow, runtime: runtime, xudpGeneration: 1, presenceLease: &xudpTestLease{active: &active}}
	current := &Session{XUDP: flow, runtime: runtime, xudpGeneration: 2, presenceLease: &xudpTestLease{active: &active}}
	flow.Attachment = current
	runtime.xudp[key] = flow

	_ = old.Close(false)
	if flow.Attachment != current || flow.Status != Active {
		t.Fatal("stale detach changed the current XUDP attachment")
	}
	if active != 1 {
		t.Fatalf("stale attachment lease count = %d; want 1", active)
	}

	_ = current.Close(false)
	if flow.Attachment != nil || flow.Status != Expiring {
		t.Fatal("current detach did not leave an offline cached backend")
	}
	if active != 0 {
		t.Fatalf("cached backend retained %d presence leases; want 0", active)
	}
}

func TestXUDPPrecommitAbortPreservesOldAttachment(t *testing.T) {
	runtime := NewRuntime()
	t.Cleanup(func() { _ = runtime.Close() })
	key := runtime.xudpKey(session.PresenceScope{}, session.PresenceModeLegacy, [8]byte{2})
	old := &Session{}
	flow := &XUDP{GlobalID: key.GlobalID, Status: Initializing, Preparing: true, Attachment: old}
	runtime.xudp[key] = flow
	worker := &ServerWorker{runtime: runtime}

	worker.abortXUDPPreparation(key, flow, false)
	if flow.Attachment != old || flow.Preparing || flow.Status != Active {
		t.Fatal("precommit abort mutated the old XUDP attachment")
	}
}

func TestXUDPInputPumpRejectsStaleGeneration(t *testing.T) {
	runtime := NewRuntime()
	requestReader, requestWriter := pipe.New(pipe.WithoutSizeLimit())
	responseReader, _ := pipe.New(pipe.WithoutSizeLimit())
	flow := newXUDPFlow(runtime, [8]byte{3})
	flow.Input = responseReader
	flow.Output = requestWriter
	flow.Status = Active
	flow.Generation = 2
	current := &Session{XUDP: flow, runtime: runtime, xudpGeneration: 2}
	flow.Attachment = current
	runtime.xudp[xudpKey{GlobalID: flow.GlobalID}] = flow
	flow.startPumps()
	t.Cleanup(func() { _ = runtime.Close() })

	if err := (&xudpAttachmentWriter{flow: flow, generation: 1}).WriteMultiBuffer(testMultiBuffer("stale")); err == nil {
		t.Fatal("stale generation write succeeded")
	}
	if err := (&xudpAttachmentWriter{flow: flow, generation: 2}).WriteMultiBuffer(testMultiBuffer("current")); err != nil {
		t.Fatalf("current generation write failed: %v", err)
	}
	payload, err := requestReader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(payload)
	if got := string(payload[0].Bytes()); got != "current" {
		t.Fatalf("backend payload = %q; want current", got)
	}
}

type xudpBlockingReader struct {
	once    sync.Once
	release chan struct{}
}

func newXUDPBlockingReader() *xudpBlockingReader {
	return &xudpBlockingReader{release: make(chan struct{})}
}

func (r *xudpBlockingReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	<-r.release
	return nil, io.ErrClosedPipe
}

func (r *xudpBlockingReader) Interrupt() { r.once.Do(func() { close(r.release) }) }

type xudpBlockingWriter struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func newXUDPBlockingWriter() *xudpBlockingWriter {
	return &xudpBlockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
}

func (w *xudpBlockingWriter) WriteMultiBuffer(payload buf.MultiBuffer) error {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	buf.ReleaseMulti(payload)
	return io.ErrClosedPipe
}

func (w *xudpBlockingWriter) Interrupt() { closeOnce(w.release) }
func (w *xudpBlockingWriter) Close() error {
	w.Interrupt()
	return nil
}

func closeOnce(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
	}
}

func TestXUDPBlockedBackendDoesNotBlockGenerationSwitchOrShutdown(t *testing.T) {
	for iteration := range 100 {
		runtime := NewRuntime()
		backendInput := newXUDPBlockingReader()
		backendOutput := newXUDPBlockingWriter()
		flow := newXUDPFlow(runtime, [8]byte{4})
		flow.Input = backendInput
		flow.Output = backendOutput
		flow.Status = Active
		flow.Generation = 1
		old := &Session{XUDP: flow, runtime: runtime, xudpGeneration: 1}
		flow.Attachment = old
		runtime.xudp[xudpKey{GlobalID: flow.GlobalID}] = flow
		flow.startPumps()

		writeDone := make(chan error, 1)
		go func() {
			writeDone <- (&xudpAttachmentWriter{flow: flow, generation: 1}).WriteMultiBuffer(testMultiBuffer("blocked"))
		}()
		select {
		case <-backendOutput.entered:
		case <-time.After(time.Second):
			t.Fatalf("iteration %d: backend write did not block", iteration)
		}

		runtime.xudpMu.Lock()
		flow.Generation = 2
		current := &Session{XUDP: flow, runtime: runtime, xudpGeneration: 2}
		flow.Attachment = current
		runtime.xudpMu.Unlock()

		closeDone := make(chan error, 1)
		go func() { closeDone <- runtime.Close() }()
		select {
		case err := <-closeDone:
			if err != nil {
				t.Fatalf("iteration %d: runtime close: %v", iteration, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("iteration %d: blocked backend prevented shutdown", iteration)
		}
		select {
		case <-writeDone:
		case <-time.After(time.Second):
			t.Fatalf("iteration %d: blocked generation writer leaked", iteration)
		}
	}
}

type xudpSignalingWriter struct {
	writer  buf.Writer
	entered chan struct{}
	once    sync.Once
}

func (w *xudpSignalingWriter) WriteMultiBuffer(payload buf.MultiBuffer) error {
	w.once.Do(func() { close(w.entered) })
	return w.writer.WriteMultiBuffer(payload)
}

func TestXUDPBlockedOldCarrierOutputDoesNotBlockRebind(t *testing.T) {
	runtime := NewRuntime()
	backendReader, backendWriter := pipe.New(pipe.WithoutSizeLimit())
	attachmentReader, attachmentWriter := pipe.New(pipe.WithSizeLimit(1))
	if err := attachmentWriter.WriteMultiBuffer(testMultiBuffer("full")); err != nil {
		t.Fatal(err)
	}
	signalingSink := &xudpSignalingWriter{writer: attachmentWriter, entered: make(chan struct{})}
	flow := newXUDPFlow(runtime, [8]byte{5})
	flow.Input = backendReader
	flow.Output = &discardingXUDPWriter{}
	flow.Status = Active
	flow.Generation = 1
	old := &Session{input: attachmentReader, xudpSink: signalingSink, XUDP: flow, runtime: runtime, xudpGeneration: 1}
	flow.Attachment = old
	runtime.xudp[xudpKey{GlobalID: flow.GlobalID}] = flow
	flow.startPumps()
	t.Cleanup(func() { _ = runtime.Close() })

	if err := backendWriter.WriteMultiBuffer(testMultiBuffer("response")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-signalingSink.entered:
	case <-time.After(time.Second):
		t.Fatal("output router did not reach the blocked old carrier sink")
	}

	newReader, newSink := pipe.New(pipe.WithoutSizeLimit())
	runtime.xudpMu.Lock()
	flow.Generation = 2
	current := &Session{input: newReader, xudpSink: newSink, XUDP: flow, runtime: runtime, xudpGeneration: 2}
	flow.Attachment = current
	runtime.xudpMu.Unlock()
	if err := old.Close(false); err != nil {
		t.Fatal(err)
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- runtime.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked old carrier output prevented shutdown")
	}
}

type discardingXUDPWriter struct{}

func (*discardingXUDPWriter) WriteMultiBuffer(payload buf.MultiBuffer) error {
	buf.ReleaseMulti(payload)
	return nil
}

func (*discardingXUDPWriter) Close() error { return nil }

func testMultiBuffer(value string) buf.MultiBuffer {
	return buf.MultiBuffer{buf.FromBytes([]byte(value))}
}
