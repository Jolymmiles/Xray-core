package mux

import (
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

const xudpInputQueueSize = 16

type xudpWriteRequest struct {
	generation uint64
	payload    buf.MultiBuffer
	result     chan error
}

type xudpAttachmentWriter struct {
	flow       *XUDP
	generation uint64
}

func (w *xudpAttachmentWriter) WriteMultiBuffer(payload buf.MultiBuffer) error {
	if w == nil || w.flow == nil {
		buf.ReleaseMulti(payload)
		return io.ErrClosedPipe
	}
	return w.flow.enqueue(w.generation, payload)
}

func newXUDPFlow(runtime *Runtime, globalID [8]byte) *XUDP {
	flow := &XUDP{GlobalID: globalID, runtime: runtime}
	flow.initPumps()
	return flow
}

func (x *XUDP) initPumps() {
	x.initOnce.Do(func() {
		x.inputQueue = make(chan xudpWriteRequest, xudpInputQueueSize)
		x.stop = make(chan struct{})
	})
}

func (x *XUDP) setBackend(input buf.Reader, output buf.Writer) bool {
	x.initPumps()
	x.sendMu.Lock()
	defer x.sendMu.Unlock()
	if x.stopped {
		return false
	}
	x.Input = input
	x.Output = output
	return true
}

func (x *XUDP) startPumps() {
	if x == nil {
		return
	}
	x.initPumps()
	x.pumpOnce.Do(func() {
		x.pumpWG.Add(2)
		go x.runInputPump()
		go x.runOutputRouter()
	})
}

func (x *XUDP) enqueue(generation uint64, payload buf.MultiBuffer) error {
	x.initPumps()
	request := xudpWriteRequest{
		generation: generation,
		payload:    payload,
		result:     make(chan error, 1),
	}

	// Interrupt takes the write side of this lock before closing stop. This
	// prevents a sender from entering the queue after the pump has drained it.
	x.sendMu.RLock()
	if x.stopped {
		x.sendMu.RUnlock()
		buf.ReleaseMulti(payload)
		return io.ErrClosedPipe
	}
	select {
	case x.inputQueue <- request:
		x.sendMu.RUnlock()
	case <-x.stop:
		x.sendMu.RUnlock()
		buf.ReleaseMulti(payload)
		return io.ErrClosedPipe
	}

	select {
	case err := <-request.result:
		return err
	case <-x.stop:
		return io.ErrClosedPipe
	}
}

func (x *XUDP) runInputPump() {
	defer x.pumpWG.Done()
	for {
		select {
		case request := <-x.inputQueue:
			x.writeInput(request)
		case <-x.stop:
			for {
				select {
				case request := <-x.inputQueue:
					buf.ReleaseMulti(request.payload)
					request.result <- io.ErrClosedPipe
				default:
					return
				}
			}
		}
	}
}

func (x *XUDP) writeInput(request xudpWriteRequest) {
	if !x.isCurrentGeneration(request.generation) {
		buf.ReleaseMulti(request.payload)
		request.result <- io.ErrClosedPipe
		return
	}
	if x.Output == nil {
		buf.ReleaseMulti(request.payload)
		request.result <- io.ErrClosedPipe
		return
	}
	request.result <- x.Output.WriteMultiBuffer(request.payload)
}

func (x *XUDP) runOutputRouter() {
	defer x.pumpWG.Done()
	for {
		if x.Input == nil {
			return
		}
		payload, err := x.Input.ReadMultiBuffer()
		if err != nil {
			buf.ReleaseMulti(payload)
			x.closeCurrentAttachment()
			return
		}
		attachment := x.currentAttachment()
		if attachment == nil || attachment.input == nil {
			buf.ReleaseMulti(payload)
			continue
		}
		writer := attachment.xudpSink
		if writer == nil {
			buf.ReleaseMulti(payload)
			continue
		}
		if err := writer.WriteMultiBuffer(payload); err != nil && x.isCurrentAttachment(attachment) {
			_ = attachment.Close(false)
		}
	}
}

func (x *XUDP) currentAttachment() *Session {
	if x == nil || x.runtime == nil {
		return nil
	}
	x.runtime.xudpMu.Lock()
	defer x.runtime.xudpMu.Unlock()
	return x.Attachment
}

func (x *XUDP) isCurrentGeneration(generation uint64) bool {
	if x == nil || x.runtime == nil {
		return false
	}
	x.runtime.xudpMu.Lock()
	defer x.runtime.xudpMu.Unlock()
	return x.Attachment != nil && x.Generation == generation && x.Attachment.xudpGeneration == generation
}

func (x *XUDP) isCurrentAttachment(attachment *Session) bool {
	if x == nil || x.runtime == nil {
		return false
	}
	x.runtime.xudpMu.Lock()
	defer x.runtime.xudpMu.Unlock()
	return x.Attachment == attachment && x.Generation == attachment.xudpGeneration
}

func (x *XUDP) closeCurrentAttachment() {
	attachment := x.currentAttachment()
	if attachment != nil {
		_ = attachment.Close(false)
	}
}

func (x *XUDP) interrupt() {
	if x == nil {
		return
	}
	x.initPumps()
	x.stopOnce.Do(func() {
		x.sendMu.Lock()
		x.stopped = true
		close(x.stop)
		x.sendMu.Unlock()
		x.closeCurrentAttachment()
		common.Interrupt(x.Input)
		common.Interrupt(x.Output)
		_ = common.Close(x.Output)
	})
}

func (x *XUDP) waitPumps() {
	if x == nil {
		return
	}
	x.pumpWG.Wait()
}
