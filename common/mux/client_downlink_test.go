package mux

// The edges of the downlink takeover that a whole worker does not reach
// deterministically: a reader that starts or stops around the takeover, what
// the downlink still holds when sorting stops early, and how a tail reports
// a failed write.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// failsFirstRead is a downlink whose first read fails before anything is
// fetched, and which counts its reads.
type failsFirstRead struct {
	*pipe.Reader
	reads int
}

func (r *failsFirstRead) ReadMultiBuffer() (buf.MultiBuffer, error) {
	r.reads++
	if r.reads == 1 {
		return nil, io.ErrUnexpectedEOF
	}
	return r.Reader.ReadMultiBuffer()
}

// A takeover whose sorting stops before the downlink's end lets go of what
// the downlink still holds, and a reader that starts only after the takeover
// reads nothing.
func TestTakeoverReleasesTheDownlinkAndKeepsALateReaderOut(t *testing.T) {
	log.RegisterHandler(discardRecords{})
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	downlink, carrierSide := pipe.New()
	defer downlink.Interrupt()
	if err := rawFrame(&transport.Link{Writer: carrierSide}, FrameMetadata{SessionStatus: SessionStatusKeepAlive}, nil); err != nil {
		t.Fatal(err)
	}
	if err := carrierSide.Close(); err != nil {
		t.Fatal(err)
	}
	reader := &failsFirstRead{Reader: downlink}
	worker := &ClientWorker{sessionManager: newClientSessionManager(), done: done.New(), link: transport.Link{Reader: downlink}}
	worker.downlink.reader = &buf.BufferedReader{Reader: reader}

	worker.takeDownlink()
	reads := reader.reads
	worker.fetchOutput()
	if reader.reads != reads {
		t.Errorf("a reader that started after the takeover read the downlink %d more times", reader.reads-reads)
	}
	left, err := downlink.ReadMultiBufferTimeout(time.Second)
	defer buf.ReleaseMulti(left)
	if !left.IsEmpty() || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("the downlink still holds %d bytes after the takeover (read error %v)", left.Len(), err)
	}
}

// heldBytes counts what buffers still hold up to the capacity of data: a
// MultiBuffer cut to length zero still holds the buffers past its length.
func heldBytes(data buf.MultiBuffer) int32 {
	return data[:cap(data)].Len()
}

// stopsOnFirstRead is a downlink whose first read fails and says so.
type stopsOnFirstRead struct {
	*pipe.Reader
	stopped chan struct{}
	once    sync.Once
}

func (r *stopsOnFirstRead) ReadMultiBuffer() (buf.MultiBuffer, error) {
	first := false
	r.once.Do(func() { first = true })
	if first {
		close(r.stopped)
		return nil, io.ErrUnexpectedEOF
	}
	return r.Reader.ReadMultiBuffer()
}

// A reader that has stopped by itself owns the worker's end: a carrier that
// returns after it, while the reader is on its way to finish the worker,
// takes nothing over and hands out none of the frames the reader left.
func TestTakeoverLeavesAReaderThatStoppedAlone(t *testing.T) {
	log.RegisterHandler(discardRecords{})
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	downlink, carrierSide := pipe.New()
	defer downlink.Interrupt()
	reply, output := pipe.New()
	defer reply.Interrupt()
	reader := &stopsOnFirstRead{Reader: downlink, stopped: make(chan struct{})}
	worker := &ClientWorker{sessionManager: newClientSessionManager(), done: done.New(), link: transport.Link{Reader: downlink}}
	defer worker.sessionManager.close()
	worker.downlink.reader = &buf.BufferedReader{Reader: reader}
	admission := worker.sessionManager.allocate(&ClientStrategy{})
	if admission == nil || !admission.beginCommit() {
		t.Fatal("the session was not admitted")
	}
	s := &Session{output: output, done: done.New()}
	if !admission.finishCommit(s, nil) {
		t.Fatal("the session was not committed")
	}
	admission.completeCommit()
	if err := sendText(&transport.Link{Writer: carrierSide}, s.ID, "later frame"); err != nil {
		t.Fatal(err)
	}
	if err := carrierSide.Close(); err != nil {
		t.Fatal(err)
	}

	finished := make(chan struct{})
	// Holding finishOnce holds the reader between letting go of the
	// downlink and finishing the worker, where the carrier takes its turn.
	worker.finishOnce.Do(func() {
		go func() {
			defer close(finished)
			worker.fetchOutput()
		}()
		await(t, reader.stopped, "the reader to stop")
		worker.takeDownlink()
		if worker.downlink.taken {
			data, err := reply.ReadMultiBufferTimeout(time.Second)
			defer buf.ReleaseMulti(data)
			t.Errorf("the downlink was taken over after its reader stopped; the session read %q (%v)", data.String(), err)
		}
	})
	await(t, finished, "the reader to finish")
	worker.sessionManager.close()
	data, err := reply.ReadMultiBufferTimeout(time.Second)
	defer buf.ReleaseMulti(data)
	if !data.IsEmpty() || !errors.Is(err, io.EOF) {
		t.Errorf("the session read %q (%v), want only its end", data.String(), err)
	}
}

// What the worker's reader had buffered past the frame that ended it goes
// back when it finishes the worker.
func TestClientWorkerReleasesWhatItsReaderHeldWhenItEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		held := heldLine{text: "unknown status", once: new(sync.Once), entered: make(chan struct{}), resume: make(chan struct{})}
		log.RegisterHandler(held)
		defer log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter()))
		defer close(held.resume)

		uplink, uplinkWriter := pipe.New()
		defer uplink.Interrupt()
		downlink, downlinkWriter := pipe.New()
		defer downlinkWriter.Close()
		worker, err := NewClientWorker(transport.Link{Reader: downlink, Writer: uplinkWriter}, ClientStrategy{})
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close()
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
			Target: net.TCPDestination(net.LocalHostIP, 80),
		}})
		pipeApplication(t, ctx, worker)
		frames := &buf.BufferedReader{Reader: uplink}
		defer func() { buf.ReleaseMulti(frames.Buffer) }()
		var opening FrameMetadata
		if err := opening.Unmarshal(frames, false); err != nil {
			t.Fatal(err)
		}
		// One batch: a frame the worker does not know, then a keep-alive.
		batch := &buf.MultiBufferContainer{}
		defer batch.Close()
		if err := rawFrame(&transport.Link{Writer: batch}, FrameMetadata{SessionID: opening.SessionID, SessionStatus: 9}, nil); err != nil {
			t.Fatal(err)
		}
		if err := rawFrame(&transport.Link{Writer: batch}, FrameMetadata{SessionStatus: SessionStatusKeepAlive}, nil); err != nil {
			t.Fatal(err)
		}
		data, err := batch.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		if err := downlinkWriter.WriteMultiBuffer(data); err != nil {
			t.Fatal(err)
		}
		await(t, held.entered, "the report of the unknown status")
		synctest.Wait()
		worker.downlink.Lock()
		left := heldBytes(worker.downlink.reader.Buffer)
		worker.downlink.Unlock()
		if left != 0 {
			t.Fatalf("the finished reader still holds %d bytes", left)
		}
	})
}

// failingOutput is a session's output whose writes fail with err.
type failingOutput struct{ err error }

func (w failingOutput) WriteMultiBuffer(data buf.MultiBuffer) error {
	buf.ReleaseMulti(data)
	return w.err
}

// tailRecords keeps the log lines and notes one written before the session
// was closed.
type tailRecords struct {
	s           *Session
	lines       []string
	beforeClose bool
}

func (r *tailRecords) Handle(message log.Message) {
	if !r.s.done.Done() {
		r.beforeClose = true
	}
	r.lines = append(r.lines, message.String())
}

// A tail whose write fails, its own or the one under way before it, is
// reported after its session is closed; a write that met the end of its
// output is not reported.
func TestTailReportsAFailedWriteAfterItsSessionCloses(t *testing.T) {
	defer log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter()))
	for _, tc := range []struct {
		name     string
		err      error
		inFlight bool
		lines    int
	}{
		{"its own write", errors.New("the output failed"), false, 1},
		{"the write under way", errors.New("the output failed"), true, 1},
		{"its own write met the end", fmt.Errorf("the output ended: %w", io.EOF), false, 0},
		{"the write under way met the end", fmt.Errorf("the output ended: %w", io.EOF), true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Session{ID: 7, output: failingOutput{tc.err}, done: done.New()}
			records := &tailRecords{s: s}
			log.RegisterHandler(records)
			var after chan error
			if tc.inFlight {
				after = make(chan error, 1)
				after <- tc.err
			}
			deliverTail(s, &sessionTail{data: buf.MultiBuffer{buf.FromBytes([]byte("tail"))}}, after)
			if !s.done.Done() {
				t.Fatal("the session is open after its tail")
			}
			if records.beforeClose {
				t.Fatal("the failure was reported before the session was closed")
			}
			if len(records.lines) != tc.lines || (tc.lines == 1 && !strings.Contains(records.lines[0], "the output failed")) {
				t.Fatalf("logged %q, want %d report(s) of the failure", records.lines, tc.lines)
			}
		})
	}
}
