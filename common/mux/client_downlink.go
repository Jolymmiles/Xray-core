package mux

import (
	"bytes"
	"context"
	"io"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// downlink is who reads a client worker's downlink. fetchOutput holds it
// while it reads and lets go of it for the time of a write to a session, the
// one thing it does that waits for an application. When a dialing worker's
// carrier returns, nothing more will arrive and what is left is bounded, so
// the factory takes the downlink in such a moment and gives each session its
// part without waiting for another session's application.
type downlink struct {
	sync.Mutex
	reader *buf.BufferedReader
	// ended is set when fetchOutput left by itself; it finishes the worker.
	ended bool
	// taken is set when the rest of the downlink was taken over.
	taken bool
	// writing is the session fetchOutput is writing to, and frame reads
	// what is left of the frame that write came from.
	writing *Session
	frame   buf.Reader
	// written gets the result of that write once the downlink is taken.
	written chan error
}

// errDownlinkTaken tells fetchOutput to leave the downlink alone.
var errDownlinkTaken = errors.New("the downlink was taken over")

// deliver copies a frame's payload to its session as buf.Copy would: a
// write that fails with the end of its output stops the frame without an
// error, another failed write comes back apart from what reading the frame
// returned. It is entered and left with the downlink held.
func (m *ClientWorker) deliver(s *Session, frame buf.Reader) (writeErr, err error) {
	dl := &m.downlink
	for {
		data, readErr := frame.ReadMultiBuffer()
		if !data.IsEmpty() {
			dl.writing, dl.frame = s, frame
			dl.Unlock()
			writeErr = s.output.WriteMultiBuffer(data)
			dl.Lock()
			if dl.taken {
				dl.written <- writeErr
				return nil, errDownlinkTaken
			}
			dl.writing, dl.frame = nil, nil
			if writeErr != nil {
				if errors.Cause(writeErr) == io.EOF {
					return nil, nil
				}
				return writeErr, nil
			}
		}
		if readErr != nil {
			if errors.Cause(readErr) == io.EOF {
				return nil, nil
			}
			return nil, readErr
		}
	}
}

// sessionTail is what the downlink still held for one session when its
// carrier returned.
type sessionTail struct {
	data buf.MultiBuffer
}

// takeDownlink takes over what is left of the downlink of a worker whose
// carrier has returned, with the downlink's far end closed and the uplink
// interrupted, so that fetchOutput is in a write to a session or gone. Each
// session with something left gets it from a goroutine of its own and is
// closed after it; every other session is closed at once, and none is
// admitted any more. The goroutines last as long as their sessions: an
// application that reads, leaves or is cancelled ends one, and so does
// closing the worker.
func (m *ClientWorker) takeDownlink() {
	dl := &m.downlink
	dl.Lock()
	if dl.ended {
		dl.Unlock()
		return
	}
	dl.taken = true
	dl.written = make(chan error, 1)
	inFlight, written := dl.writing, dl.written
	tails, parseErr := m.sortDownlink()
	// Nobody reads the downlink any more: what a remainder that could not
	// be parsed left in it goes back, and the worker lets go of the session
	// it was writing to.
	dl.writing, dl.frame = nil, nil
	dl.reader.Buffer = buf.ReleaseMulti(dl.reader.Buffer)
	common.Interrupt(m.link.Reader)
	dl.Unlock()

	// The deliveries start before the other sessions are closed: closing
	// an output may wait for its application too.
	kept := make(map[*Session]struct{}, len(tails))
	for s, tail := range tails {
		kept[s] = struct{}{}
		var after <-chan error
		if s == inFlight {
			after = written
		}
		go deliverTail(s, tail, after)
	}
	m.sessionManager.closeExcept(kept)
	if parseErr != nil {
		errors.LogInfoInner(context.Background(), parseErr, "failed to read the rest of the downlink")
	}
}

// sortDownlink reads the downlink to its end and sorts what it holds by
// session. It is called with the downlink held and its far end closed, so no
// read waits. Nothing is written back: the uplink is gone. A frame for a
// session that is gone or has had its END is skipped, and so is what a NEW or
// a keep-alive carries. Reading stops at a frame it cannot make out; what
// came before it stands.
func (m *ClientWorker) sortDownlink() (map[*Session]*sessionTail, error) {
	dl := &m.downlink
	tails := make(map[*Session]*sessionTail)
	tailOf := func(s *Session) *sessionTail {
		if tails[s] == nil {
			tails[s] = new(sessionTail)
		}
		return tails[s]
	}
	ended := make(map[*Session]struct{})
	if dl.writing != nil {
		if err := tailOf(dl.writing).collect(dl.writing, dl.frame); err != nil {
			return tails, err
		}
	}
	skip := func(meta *FrameMetadata) error {
		if !meta.Option.Has(OptionData) {
			return nil
		}
		return buf.Copy(NewStreamReader(dl.reader), buf.Discard)
	}
	var meta FrameMetadata
	for {
		if err := meta.Unmarshal(dl.reader, false); err != nil {
			if errors.Cause(err) == io.EOF {
				return tails, nil
			}
			return tails, err
		}
		var err error
		switch meta.SessionStatus {
		case SessionStatusKeep:
			s, found := m.sessionManager.active(meta.SessionID)
			if _, over := ended[s]; !found || over || !meta.Option.Has(OptionData) {
				err = skip(&meta)
				break
			}
			err = tailOf(s).collect(s, s.NewReader(dl.reader, &meta.Target))
		case SessionStatusEnd:
			if s, found := m.sessionManager.active(meta.SessionID); found {
				ended[s] = struct{}{}
			}
			err = skip(&meta)
		case SessionStatusNew, SessionStatusKeepAlive:
			err = skip(&meta)
		default:
			return tails, errors.New("unknown status: ", meta.SessionStatus)
		}
		if err != nil {
			return tails, err
		}
	}
}

// collect reads a frame's payload into the tail. A stream's bytes are packed
// into as few buffers as they need and a packet is copied to its own size:
// the frames may be many and small, and each would hold a whole buffer.
func (t *sessionTail) collect(s *Session, frame buf.Reader) error {
	for {
		data, err := frame.ReadMultiBuffer()
		for _, b := range data {
			if b.IsEmpty() {
				continue
			}
			if s.transferType == protocol.TransferTypeStream {
				t.data = buf.MergeBytes(t.data, b.Bytes())
				continue
			}
			packet := buf.FromBytes(bytes.Clone(b.Bytes()))
			packet.UDP = b.UDP
			t.data = append(t.data, packet)
		}
		buf.ReleaseMulti(data)
		if err != nil {
			if errors.Cause(err) == io.EOF {
				return nil
			}
			return err
		}
	}
}

// deliverTail writes a session's tail to it, buffer by buffer, which keeps a
// packet session's datagrams apart, and closes the session. After is the
// result of the write fetchOutput had begun, if it was this session's: the
// tail follows it, and is dropped if it failed. A failed write is reported
// after the session is closed, as the worker's reader reports it.
func deliverTail(s *Session, tail *sessionTail, after <-chan error) {
	data := tail.data
	var writeErr error
	defer func() {
		buf.ReleaseMulti(data)
		s.Close(false)
		if writeErr != nil && errors.Cause(writeErr) != io.EOF {
			errors.LogInfoInner(context.Background(), writeErr, "failed to write to downstream. closing session ", s.ID)
		}
	}()
	if after != nil {
		if writeErr = <-after; writeErr != nil {
			return
		}
	}
	for !data.IsEmpty() {
		var next *buf.Buffer
		data, next = buf.SplitFirst(data)
		if writeErr = s.output.WriteMultiBuffer(buf.MultiBuffer{next}); writeErr != nil {
			return
		}
	}
}

// report logs what went wrong with one session's frame while the worker
// goes on, with the downlink let go: a log handler takes its time, and a
// carrier that returns meanwhile must find the downlink free. It is entered
// and left with the downlink held, and tells whether the downlink was taken
// meanwhile.
func (m *ClientWorker) report(err error, values ...interface{}) (taken bool) {
	dl := &m.downlink
	dl.Unlock()
	errors.LogInfoInner(context.Background(), err, values...)
	dl.Lock()
	return dl.taken
}
