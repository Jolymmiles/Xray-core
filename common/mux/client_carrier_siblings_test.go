package mux

import (
	"context"
	"errors"
	"fmt"
	"io"
	gonet "net"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// application is the application's side of one session: what it reads of
// its reply, and how its link reaches the worker.
type application struct {
	// read returns the next piece of the reply, io.EOF at its end, or
	// another error when nothing came in time.
	read func() (string, error)
	// abort makes the write of the reply fail.
	abort func()
}

// readAll reads the reply to its end.
func (a application) readAll(t *testing.T) string {
	t.Helper()
	var reply string
	for {
		piece, err := a.read()
		reply += piece
		if errors.Is(err, io.EOF) {
			return reply
		}
		if err != nil {
			t.Fatalf("read %q, then: %v", reply, err)
		}
	}
}

// pipeApplication dispatches a session the way an inbound that uses Dispatch
// does: through pipes. Its reply pipe holds one write.
func pipeApplication(t *testing.T, ctx context.Context, worker *ClientWorker) application {
	t.Helper()
	upload, send := pipe.New(pipe.WithSizeLimit(0))
	reply, output := pipe.New(pipe.WithSizeLimit(0))
	t.Cleanup(func() { _ = send.Close(); reply.Interrupt() })
	if !worker.Dispatch(ctx, &transport.Link{Reader: upload, Writer: output}) {
		t.Fatal("the worker refused a session")
	}
	return application{
		read: func() (string, error) {
			data, err := reply.ReadMultiBufferTimeout(time.Second)
			defer buf.ReleaseMulti(data)
			return data.String(), err
		},
		abort: reply.Interrupt,
	}
}

// connApplication dispatches a session the way an inbound that hands its
// connection over does: the session reads and writes the connection itself,
// Dispatch returns when the session is done, and the inbound then closes the
// connection. A write to it waits for the application to read.
func connApplication(t *testing.T, ctx context.Context, worker *ClientWorker) application {
	t.Helper()
	app, inbound := gonet.Pipe()
	t.Cleanup(func() { _ = app.Close(); _ = inbound.Close() })
	accepted := make(chan bool, 1)
	go func() {
		ok := worker.Dispatch(ctx, &transport.Link{Reader: buf.NewReader(inbound), Writer: buf.NewWriter(inbound)})
		accepted <- ok
		_ = inbound.Close()
	}()
	t.Cleanup(func() {
		select {
		case ok := <-accepted:
			if !ok {
				t.Error("the worker refused a session")
			}
		default:
		}
	})
	return application{
		read: func() (string, error) {
			// Refused once the inbound has closed its end; the read then
			// returns the end at once.
			_ = app.SetReadDeadline(time.Now().Add(time.Second))
			piece := make([]byte, 64)
			n, err := app.Read(piece)
			return string(piece[:n]), err
		},
		abort: func() { _ = app.Close() },
	}
}

// repliesThenReturns is a carrier that takes the opening frames of three
// sessions, writes three frames for the first and one for the second, none
// for the third, and returns result once released.
func repliesThenReturns(release <-chan struct{}, result error, opened chan<- []uint16) carrierFunc {
	return func(link *transport.Link) error {
		reader := &buf.BufferedReader{Reader: link.Reader}
		defer func() { buf.ReleaseMulti(reader.Buffer) }()
		var ids []uint16
		for len(ids) < 3 {
			var frame FrameMetadata
			if err := frame.Unmarshal(reader, false); err != nil {
				return err
			}
			if frame.SessionStatus != SessionStatusNew {
				return fmt.Errorf("expected a NEW, got %+v", frame)
			}
			ids = append(ids, frame.SessionID)
		}
		slices.Sort(ids)
		opened <- ids
		send := func(id uint16, text string) error {
			block := buf.New()
			if _, err := block.WriteString(text); err != nil {
				block.Release()
				return err
			}
			return NewResponseWriter(id, link.Writer, protocol.TransferTypeStream).WriteMultiBuffer(buf.MultiBuffer{block})
		}
		for _, text := range []string{"s1", "s2", "s3"} {
			if err := send(ids[0], text); err != nil {
				return err
			}
		}
		if err := send(ids[1], "fast reply"); err != nil {
			return err
		}
		<-release
		return result
	}
}

// After its carrier has returned, a worker gives every session what the
// carrier had written for it, and its end, without waiting for another
// session's application. The first session's application reads nothing: the
// worker's reader is held on a write to it, with more of its reply and a
// sibling's reply behind that write. The sibling gets its reply and its end,
// a third session with no reply gets its end, and the first, when it reads
// at last, gets its whole reply in order and its end.
func TestDialingWorkerEndsSiblingsOfASessionThatDoesNotRead(t *testing.T) {
	log.RegisterHandler(discardRecords{})
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	kinds := map[string]func(*testing.T, context.Context, *ClientWorker) application{
		"pipes":       pipeApplication,
		"connections": connApplication,
	}
	results := map[string]error{"the carrier fails": errors.New("connection reset"), "the carrier ends": nil}
	for kind, dispatch := range kinds {
		for how, result := range results {
			t.Run(kind+"/"+how, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					release := make(chan struct{})
					letReturn := sync.OnceFunc(func() { close(release) })
					defer letReturn()
					opened := make(chan []uint16, 1)
					worker, err := (&DialingWorkerFactory{Proxy: repliesThenReturns(release, result, opened)}).Create()
					if err != nil {
						t.Fatal(err)
					}
					defer worker.Close()
					ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
						Target: net.TCPDestination(net.LocalHostIP, 80),
					}})
					// Sessions get their ids in the order they are dispatched.
					slow := dispatch(t, ctx, worker)
					synctest.Wait()
					fast := dispatch(t, ctx, worker)
					synctest.Wait()
					silent := dispatch(t, ctx, worker)
					await(t, opened, "the carrier to take three opening frames")
					synctest.Wait()

					letReturn()
					await(t, worker.WaitClosed(), "the worker to close")
					synctest.Wait()

					if reply := fast.readAll(t); reply != "fast reply" {
						t.Fatalf("the sibling read %q, want its reply %q", reply, "fast reply")
					}
					if reply := silent.readAll(t); reply != "" {
						t.Fatalf("the session without a reply read %q", reply)
					}
					synctest.Wait()
					if active := worker.ActiveConnections(); active != 1 {
						t.Fatalf("%d sessions while one application does not read, want that one only", active)
					}

					if reply := slow.readAll(t); reply != "s1s2s3" {
						t.Fatalf("the slow session read %q, want its whole reply %q", reply, "s1s2s3")
					}
					synctest.Wait()
					if active := worker.ActiveConnections(); active != 0 {
						t.Fatalf("%d sessions after every reply was read, want none", active)
					}
				})
			})
		}
	}
}

// With a live carrier the order of the downlink stands: Mux.Cool has no flow
// control of its own, and a session whose application does not read holds
// what follows it.
func TestClientWorkerKeepsTheDownlinkInOrderWhileItsCarrierLives(t *testing.T) {
	log.RegisterHandler(discardRecords{})
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		letReturn := sync.OnceFunc(func() { close(release) })
		defer letReturn()
		opened := make(chan []uint16, 1)
		worker, err := (&DialingWorkerFactory{Proxy: repliesThenReturns(release, nil, opened)}).Create()
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close()
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
			Target: net.TCPDestination(net.LocalHostIP, 80),
		}})
		slow := pipeApplication(t, ctx, worker)
		synctest.Wait()
		fast := pipeApplication(t, ctx, worker)
		synctest.Wait()
		pipeApplication(t, ctx, worker)
		await(t, opened, "the carrier to take three opening frames")
		synctest.Wait()

		if piece, err := fast.read(); err == nil || errors.Is(err, io.EOF) {
			t.Fatalf("the sibling read %q (%v) past a session that does not read, under a live carrier", piece, err)
		}
		if reply, err := slow.read(); err != nil || reply != "s1" {
			t.Fatalf("the slow session read %q (%v), want %q", reply, err, "s1")
		}
	})
}

// threeSessions dispatches three sessions through pipes on a worker whose
// carrier runs reply once it has their opening frames, with their ids in
// the order of dispatch, and returns once reply has returned and the worker
// has dealt with it.
func threeSessions(t *testing.T, targets [3]net.Destination, reply func(link *transport.Link, ids []uint16) error) (*ClientWorker, [3]application) {
	t.Helper()
	opened := make(chan []uint16, 1)
	carrier := carrierFunc(func(link *transport.Link) error {
		reader := &buf.BufferedReader{Reader: link.Reader}
		defer func() { buf.ReleaseMulti(reader.Buffer) }()
		var ids []uint16
		for len(ids) < 3 {
			var frame FrameMetadata
			if err := frame.Unmarshal(reader, false); err != nil {
				return err
			}
			if frame.SessionStatus != SessionStatusNew {
				return fmt.Errorf("expected a NEW, got %+v", frame)
			}
			ids = append(ids, frame.SessionID)
		}
		slices.Sort(ids)
		opened <- ids
		if err := reply(link, ids); err != nil {
			return err
		}
		return errors.New("connection reset")
	})
	worker, err := (&DialingWorkerFactory{Proxy: carrier}).Create()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = worker.Close() })
	var applications [3]application
	for i, target := range targets {
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: target}})
		applications[i] = pipeApplication(t, ctx, worker)
		synctest.Wait()
	}
	await(t, opened, "the carrier to take three opening frames")
	await(t, worker.WaitClosed(), "the worker to close")
	synctest.Wait()
	return worker, applications
}

// sendText writes one frame of a stream session's reply.
func sendText(link *transport.Link, id uint16, text string) error {
	block := buf.New()
	if _, err := block.WriteString(text); err != nil {
		block.Release()
		return err
	}
	return NewResponseWriter(id, link.Writer, protocol.TransferTypeStream).WriteMultiBuffer(buf.MultiBuffer{block})
}

var tcpTargets = [3]net.Destination{
	net.TCPDestination(net.LocalHostIP, 80),
	net.TCPDestination(net.LocalHostIP, 80),
	net.TCPDestination(net.LocalHostIP, 80),
}

// A frame of the reply may reach the worker in pieces. When the piece being
// written is the one the worker's reader is held on, the rest of that frame
// follows it, in order, before what later frames bring.
func TestDialingWorkerDeliversTheRestOfAFrameItWasWriting(t *testing.T) {
	log.RegisterHandler(discardRecords{})
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	synctest.Test(t, func(t *testing.T) {
		_, apps := threeSessions(t, tcpTargets, func(link *transport.Link, ids []uint16) error {
			// The first frame fills the application's pipe.
			if err := sendText(link, ids[0], "a"); err != nil {
				return err
			}
			// One frame of six bytes, in two writes of the carrier.
			head := buf.New()
			meta := FrameMetadata{SessionID: ids[0], SessionStatus: SessionStatusKeep}
			meta.Option.Set(OptionData)
			if err := meta.WriteTo(head); err != nil {
				return err
			}
			if _, err := serial.WriteUint16(head, 6); err != nil {
				return err
			}
			if _, err := head.WriteString("bcd"); err != nil {
				return err
			}
			if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{head}); err != nil {
				return err
			}
			// The worker's reader has the first half and is held on it.
			synctest.Wait()
			rest := buf.New()
			if _, err := rest.WriteString("efg"); err != nil {
				return err
			}
			if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{rest}); err != nil {
				return err
			}
			if err := sendText(link, ids[0], "h"); err != nil {
				return err
			}
			return sendText(link, ids[1], "sibling")
		})
		if reply := apps[1].readAll(t); reply != "sibling" {
			t.Fatalf("the sibling read %q, want %q", reply, "sibling")
		}
		if reply := apps[0].readAll(t); reply != "abcdefgh" {
			t.Fatalf("the slow session read %q, want %q", reply, "abcdefgh")
		}
	})
}

// What the downlink still holds is sorted as the worker's reader would have
// read it: a session's END ends it after what came before, a frame for a
// session that is gone or over is skipped with its payload, and so is what
// a keep-alive carries. A remainder that cannot be made out ends the
// sorting, and what came before it stands.
func TestDialingWorkerSortsWhatItsCarrierLeft(t *testing.T) {
	log.RegisterHandler(discardRecords{})
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	synctest.Test(t, func(t *testing.T) {
		worker, apps := threeSessions(t, tcpTargets, func(link *transport.Link, ids []uint16) error {
			for _, text := range []string{"s1", "s2"} {
				if err := sendText(link, ids[0], text); err != nil {
					return err
				}
			}
			if err := sendText(link, 0xfff0, "for a session that is gone"); err != nil {
				return err
			}
			alive := buf.New()
			meta := FrameMetadata{SessionStatus: SessionStatusKeepAlive}
			meta.Option.Set(OptionData)
			if err := meta.WriteTo(alive); err != nil {
				return err
			}
			if _, err := serial.WriteUint16(alive, 4); err != nil {
				return err
			}
			if _, err := alive.WriteString("ping"); err != nil {
				return err
			}
			if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{alive}); err != nil {
				return err
			}
			if err := sendText(link, ids[1], "sibling"); err != nil {
				return err
			}
			if err := NewResponseWriter(ids[1], link.Writer, protocol.TransferTypeStream).Close(); err != nil {
				return err
			}
			if err := sendText(link, ids[1], "after its end"); err != nil {
				return err
			}
			if err := sendText(link, ids[0], "s3"); err != nil {
				return err
			}
			// A frame whose metadata claims more than a frame's may hold.
			junk := buf.New()
			if _, err := junk.Write([]byte{0xff, 0xff, 1, 2, 3}); err != nil {
				return err
			}
			if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{junk}); err != nil {
				return err
			}
			return sendText(link, ids[0], "after the junk")
		})
		if reply := apps[1].readAll(t); reply != "sibling" {
			t.Fatalf("the sibling read %q, want %q", reply, "sibling")
		}
		if reply := apps[2].readAll(t); reply != "" {
			t.Fatalf("the session without a reply read %q", reply)
		}
		if reply := apps[0].readAll(t); reply != "s1s2s3" {
			t.Fatalf("the slow session read %q, want %q", reply, "s1s2s3")
		}
		synctest.Wait()
		if active := worker.ActiveConnections(); active != 0 {
			t.Fatalf("%d sessions after every reply was read, want none", active)
		}
	})
}

// A packet session's datagrams stay whole and keep their sources when they
// are handed out behind another session's held write.
func TestDialingWorkerKeepsDatagramsApartBehindASessionThatDoesNotRead(t *testing.T) {
	log.RegisterHandler(discardRecords{})
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	synctest.Test(t, func(t *testing.T) {
		sources := []net.Destination{
			net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 53),
			net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 2}), 5353),
		}
		targets := tcpTargets
		targets[1] = net.UDPDestination(net.LocalHostIP, 53)
		opened := make(chan []uint16, 1)
		carrier := carrierFunc(func(link *transport.Link) error {
			reader := &buf.BufferedReader{Reader: link.Reader}
			defer func() { buf.ReleaseMulti(reader.Buffer) }()
			var ids []uint16
			for len(ids) < 3 {
				var frame FrameMetadata
				if err := frame.Unmarshal(reader, false); err != nil {
					return err
				}
				ids = append(ids, frame.SessionID)
			}
			slices.Sort(ids)
			opened <- ids
			for _, text := range []string{"s1", "s2"} {
				if err := sendText(link, ids[0], text); err != nil {
					return err
				}
			}
			packets := NewResponseWriter(ids[1], link.Writer, protocol.TransferTypePacket)
			for i, text := range []string{"first datagram", "second"} {
				packet := buf.New()
				if _, err := packet.WriteString(text); err != nil {
					return err
				}
				packet.UDP = &sources[i]
				if err := packets.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
					return err
				}
			}
			return errors.New("connection reset")
		})
		worker, err := (&DialingWorkerFactory{Proxy: carrier}).Create()
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close()
		pipeApplication(t, session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: targets[0]}}), worker)
		synctest.Wait()
		// The packet session's reply pipe takes every datagram.
		upload, send := pipe.New(pipe.WithSizeLimit(0))
		defer send.Close()
		reply, output := pipe.New()
		defer reply.Interrupt()
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: targets[1]}})
		if !worker.Dispatch(ctx, &transport.Link{Reader: upload, Writer: output}) {
			t.Fatal("the worker refused the packet session")
		}
		synctest.Wait()
		pipeApplication(t, session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: targets[2]}}), worker)
		await(t, opened, "the carrier to take three opening frames")
		await(t, worker.WaitClosed(), "the worker to close")
		synctest.Wait()

		var datagrams buf.MultiBuffer
		defer func() { buf.ReleaseMulti(datagrams) }()
		for {
			data, err := reply.ReadMultiBufferTimeout(time.Second)
			datagrams = append(datagrams, data...)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("read %d datagrams, then: %v", len(datagrams), err)
			}
		}
		if len(datagrams) != 2 {
			t.Fatalf("the packet session read %d datagrams, want 2", len(datagrams))
		}
		for i, want := range []string{"first datagram", "second"} {
			if got := datagrams[i]; got.String() != want || got.UDP == nil || *got.UDP != sources[i] {
				t.Fatalf("datagram %d is %q from %v, want %q from %v", i, got.String(), got.UDP, want, sources[i])
			}
		}
	})
}

// A session whose reply is waiting for its application ends when the write
// it waits on fails, and when the worker is closed; what was behind that
// write goes with it.
func TestDialingWorkerEndsAWaitingSessionWhenItsWriteFailsOrTheWorkerCloses(t *testing.T) {
	log.RegisterHandler(discardRecords{})
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	for name, closeWorker := range map[string]bool{"its write fails": false, "the worker is closed": true} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				worker, apps := threeSessions(t, tcpTargets, func(link *transport.Link, ids []uint16) error {
					for _, text := range []string{"s1", "s2", "s3"} {
						if err := sendText(link, ids[0], text); err != nil {
							return err
						}
					}
					return nil
				})
				if active := worker.ActiveConnections(); active != 1 {
					t.Fatalf("%d sessions while one application does not read, want that one only", active)
				}
				if closeWorker {
					if err := worker.Close(); err != nil {
						t.Fatal(err)
					}
				} else {
					apps[0].abort()
				}
				synctest.Wait()
				if active := worker.ActiveConnections(); active != 0 {
					t.Fatalf("%d sessions, want none", active)
				}
			})
		})
	}
}

// failsItsSecondWrite passes writes on, holds the second until released and
// fails it; a later write would be taken again.
type failsItsSecondWrite struct {
	*pipe.Writer
	writes  int
	held    chan struct{}
	release <-chan struct{}
}

func (w *failsItsSecondWrite) WriteMultiBuffer(data buf.MultiBuffer) error {
	w.writes++
	if w.writes == 2 {
		buf.ReleaseMulti(data)
		close(w.held)
		<-w.release
		return errors.New("connection reset by peer")
	}
	return w.Writer.WriteMultiBuffer(data)
}

// What was behind a write that failed is not delivered: the reply would
// have a hole. The output here would take a later write again.
func TestDialingWorkerDropsWhatFollowsAWriteThatFailed(t *testing.T) {
	log.RegisterHandler(discardRecords{})
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	synctest.Test(t, func(t *testing.T) {
		carrier := carrierFunc(func(link *transport.Link) error {
			reader := &buf.BufferedReader{Reader: link.Reader}
			defer func() { buf.ReleaseMulti(reader.Buffer) }()
			var opening FrameMetadata
			if err := opening.Unmarshal(reader, false); err != nil {
				return err
			}
			for _, text := range []string{"a", "b", "c"} {
				if err := sendText(link, opening.SessionID, text); err != nil {
					return err
				}
			}
			return errors.New("connection reset")
		})
		worker, err := (&DialingWorkerFactory{Proxy: carrier}).Create()
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close()
		upload, send := pipe.New(pipe.WithSizeLimit(0))
		defer send.Close()
		reply, output := pipe.New()
		defer reply.Interrupt()
		release := make(chan struct{})
		fail := sync.OnceFunc(func() { close(release) })
		defer fail()
		sink := &failsItsSecondWrite{Writer: output, held: make(chan struct{}), release: release}
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
			Target: net.TCPDestination(net.LocalHostIP, 80),
		}})
		if !worker.Dispatch(ctx, &transport.Link{Reader: upload, Writer: sink}) {
			t.Fatal("the worker refused the session")
		}
		await(t, sink.held, "the second frame's write")
		await(t, worker.WaitClosed(), "the worker to close")
		synctest.Wait()

		fail()
		synctest.Wait()
		var body string
		for {
			data, err := reply.ReadMultiBufferTimeout(time.Second)
			body += data.String()
			buf.ReleaseMulti(data)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("read %q, then: %v", body, err)
			}
		}
		if body != "a" {
			t.Fatalf("the application read %q, want %q: what followed the failed write was delivered", body, "a")
		}
		if active := worker.ActiveConnections(); active != 0 {
			t.Fatalf("%d sessions after the write failed, want none", active)
		}
	})
}

// With a live carrier, a session whose output fails a write is closed, the
// rest of that frame is skipped, and the downlink goes on to the others.
func TestClientWorkerClosesASessionWhoseOutputFailsAndGoesOn(t *testing.T) {
	log.RegisterHandler(discardRecords{})
	t.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		letReturn := sync.OnceFunc(func() { close(release) })
		defer letReturn()
		answer := make(chan struct{})
		opened := make(chan []uint16, 1)
		carrier := carrierFunc(func(link *transport.Link) error {
			reader := &buf.BufferedReader{Reader: link.Reader}
			defer func() { buf.ReleaseMulti(reader.Buffer) }()
			var ids []uint16
			for len(ids) < 2 {
				var frame FrameMetadata
				if err := frame.Unmarshal(reader, false); err != nil {
					return err
				}
				ids = append(ids, frame.SessionID)
			}
			slices.Sort(ids)
			opened <- ids
			<-answer
			if err := sendText(link, ids[0], "for the output that fails"); err != nil {
				return err
			}
			if err := sendText(link, ids[1], "sibling"); err != nil {
				return err
			}
			<-release
			return nil
		})
		worker, err := (&DialingWorkerFactory{Proxy: carrier}).Create()
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close()
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
			Target: net.TCPDestination(net.LocalHostIP, 80),
		}})
		failing := pipeApplication(t, ctx, worker)
		synctest.Wait()
		sibling := pipeApplication(t, ctx, worker)
		await(t, opened, "the carrier to take two opening frames")
		synctest.Wait()

		failing.abort()
		close(answer)
		synctest.Wait()
		if worker.Closed() {
			t.Fatal("the worker closed under a live carrier")
		}
		if active := worker.ActiveConnections(); active != 1 {
			t.Fatalf("%d sessions after one output failed, want the sibling only", active)
		}
		if piece, err := sibling.read(); err != nil || piece != "sibling" {
			t.Fatalf("the sibling read %q (%v), want %q", piece, err, "sibling")
		}
	})
}
