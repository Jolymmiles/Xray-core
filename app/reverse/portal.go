package reverse

import (
	"context"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
	"google.golang.org/protobuf/proto"
)

type portalState uint8

const (
	portalOpen portalState = iota
	portalClosing
	portalClosed
)

type Portal struct {
	ohm    outbound.Manager
	tag    string
	domain string
	picker *StaticMuxPicker
	client *mux.ClientManager

	lifecycleMu   sync.Mutex
	state         portalState
	registrations sync.WaitGroup
	handlers      sync.WaitGroup
	closeOnce     sync.Once
	closeErr      error
}

func NewPortal(config *PortalConfig, ohm outbound.Manager) (*Portal, error) {
	if config.Tag == "" {
		return nil, errors.New("portal tag is empty")
	}

	if config.Domain == "" {
		return nil, errors.New("portal domain is empty")
	}

	picker, err := NewStaticMuxPicker()
	if err != nil {
		return nil, err
	}

	return &Portal{
		ohm:    ohm,
		tag:    config.Tag,
		domain: config.Domain,
		picker: picker,
		client: &mux.ClientManager{
			Picker: picker,
		},
	}, nil
}

func (p *Portal) Start() error {
	if !p.beginRegistration() {
		return errors.New("portal is closing")
	}
	defer p.registrations.Done()
	return p.ohm.AddHandler(context.Background(), &Outbound{
		portal: p,
		tag:    p.tag,
	})
}

func (p *Portal) Close() error {
	p.closeOnce.Do(func() {
		p.lifecycleMu.Lock()
		p.state = portalClosing
		p.lifecycleMu.Unlock()
		p.registrations.Wait()
		var removeErr error
		if p.ohm != nil {
			removeErr = p.ohm.RemoveHandler(context.Background(), p.tag)
		}
		var pickerErr error
		if p.picker != nil {
			pickerErr = p.picker.Close()
		}
		p.handlers.Wait()
		p.lifecycleMu.Lock()
		p.state = portalClosed
		p.lifecycleMu.Unlock()
		p.closeErr = errors.Combine(removeErr, pickerErr)
	})
	return p.closeErr
}

func (p *Portal) beginRegistration() bool {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	if p.state != portalOpen {
		return false
	}
	p.registrations.Add(1)
	return true
}

func (p *Portal) beginHandle() bool {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	if p.state != portalOpen {
		return false
	}
	p.handlers.Add(1)
	return true
}

func (p *Portal) endHandle() {
	p.handlers.Done()
}

func (p *Portal) HandleConnection(ctx context.Context, link *transport.Link) error {
	if !p.beginHandle() {
		return errors.New("portal is closing")
	}
	defer p.endHandle()
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if ob == nil {
		return errors.New("outbound metadata not found").AtError()
	}

	if isDomain(ob.Target, p.domain) {
		muxClient, err := mux.NewClientWorkerWithPresence(*link, mux.ClientStrategy{}, session.PresenceScopeFromContext(ctx))
		if err != nil {
			return errors.New("failed to create mux client worker").Base(err).AtWarning()
		}

		worker, err := NewPortalWorker(muxClient)
		if err != nil {
			return errors.New("failed to create portal worker").Base(err)
		}

		p.picker.AddWorker(worker)

		if _, ok := link.Reader.(*pipe.Reader); !ok {
			select {
			case <-ctx.Done():
			case <-muxClient.WaitClosed():
			}
		}
		return nil
	}

	if ob.Target.Network == net.Network_UDP && ob.OriginalTarget.Address != nil && ob.OriginalTarget.Address != ob.Target.Address {
		link.Reader = &buf.EndpointOverrideReader{Reader: link.Reader, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
		link.Writer = &buf.EndpointOverrideWriter{Writer: link.Writer, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
	}

	return p.client.DispatchRVS(ctx, link)
}

type Outbound struct {
	portal *Portal
	tag    string
}

// ClaimsPresence identifies reverse carriers before direct route ownership is
// activated. Ordinary requests through the same outbound remain direct.
func (o *Outbound) ClaimsPresence(ctx context.Context) bool {
	outbounds := session.OutboundsFromContext(ctx)
	return len(outbounds) != 0 && outbounds[len(outbounds)-1] != nil && isDomain(outbounds[len(outbounds)-1].Target, o.portal.domain)
}

func (o *Outbound) Tag() string {
	return o.tag
}

func (o *Outbound) Dispatch(ctx context.Context, link *transport.Link) {
	if err := o.portal.HandleConnection(ctx, link); err != nil {
		errors.LogInfoInner(ctx, err, "failed to process reverse connection")
		common.Interrupt(link.Writer)
		common.Interrupt(link.Reader)
	}
}

func (o *Outbound) Start() error {
	return nil
}

func (o *Outbound) Close() error {
	return nil
}

// SenderSettings implements outbound.Handler.
func (o *Outbound) SenderSettings() *serial.TypedMessage {
	return nil
}

// ProxySettings implements outbound.Handler.
func (o *Outbound) ProxySettings() *serial.TypedMessage {
	return nil
}

type StaticMuxPicker struct {
	access    sync.Mutex
	workers   []*PortalWorker
	cTask     *task.Periodic
	closed    bool
	closeOnce sync.Once
}

func NewStaticMuxPicker() (*StaticMuxPicker, error) {
	p := &StaticMuxPicker{}
	p.cTask = &task.Periodic{
		Execute:  p.cleanup,
		Interval: time.Second * 30,
	}
	p.cTask.Start()
	return p, nil
}

func (p *StaticMuxPicker) cleanup() error {
	p.access.Lock()
	var activeWorkers []*PortalWorker
	var closedWorkers []*PortalWorker
	for _, worker := range p.workers {
		if worker.Closed() {
			closedWorkers = append(closedWorkers, worker)
		} else {
			activeWorkers = append(activeWorkers, worker)
		}
	}
	if len(activeWorkers) != len(p.workers) {
		p.workers = activeWorkers
	}
	p.access.Unlock()

	var result error
	for _, worker := range closedWorkers {
		result = errors.Combine(result, worker.Close())
	}
	return result
}

func (p *StaticMuxPicker) PickAvailable() (*mux.ClientWorker, error) {
	p.access.Lock()
	defer p.access.Unlock()

	if p.closed {
		return nil, errors.New("picker is closing")
	}
	if len(p.workers) == 0 {
		return nil, errors.New("empty worker list")
	}

	var minIdx int = -1
	var minConn uint32 = 9999
	for i, w := range p.workers {
		if w.Draining() {
			continue
		}
		if w.IsFull() {
			continue
		}
		if w.client.ActiveConnections() < minConn {
			minConn = w.client.ActiveConnections()
			minIdx = i
		}
	}

	if minIdx == -1 {
		for i, w := range p.workers {
			if w.IsFull() {
				continue
			}
			if w.client.ActiveConnections() < minConn {
				minConn = w.client.ActiveConnections()
				minIdx = i
			}
		}
	}

	if minIdx != -1 {
		return p.workers[minIdx].client, nil
	}

	return nil, errors.New("no mux client worker available")
}

func (p *StaticMuxPicker) AddWorker(worker *PortalWorker) {
	p.access.Lock()
	if p.closed {
		p.access.Unlock()
		_ = worker.Close()
		return
	}
	p.workers = append(p.workers, worker)
	p.access.Unlock()
}

func (p *StaticMuxPicker) Close() error {
	var result error
	p.closeOnce.Do(func() {
		result = p.cTask.Close()
		p.access.Lock()
		p.closed = true
		workers := p.workers
		p.workers = nil
		p.access.Unlock()
		for _, worker := range workers {
			result = errors.Combine(result, worker.Close())
		}
	})
	return result
}

type PortalWorker struct {
	mu               sync.Mutex
	client           *mux.ClientWorker
	control          *task.Periodic
	writer           buf.Writer
	reader           buf.Reader
	draining         bool
	counter          uint32
	timer            *signal.ActivityTimer
	closeOnce        sync.Once
	heartbeatMu      sync.Mutex
	heartbeatClosing bool
	heartbeats       sync.WaitGroup
}

func NewPortalWorker(client *mux.ClientWorker) (*PortalWorker, error) {
	opt := []pipe.Option{pipe.WithSizeLimit(16 * 1024)}
	uplinkReader, uplinkWriter := pipe.New(opt...)
	downlinkReader, downlinkWriter := pipe.New(opt...)

	ctx := context.Background()
	outbounds := []*session.Outbound{{
		Target: net.UDPDestination(net.DomainAddress(internalDomain), 0),
	}}
	ctx = session.ContextWithOutbounds(ctx, outbounds)
	f := client.Dispatch(ctx, &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	})
	if !f {
		return nil, errors.New("unable to dispatch control connection")
	}
	terminate := func() {
		client.Close()
	}
	w := &PortalWorker{
		client: client,
		reader: downlinkReader,
		writer: uplinkWriter,
		timer:  signal.CancelAfterInactivity(ctx, terminate, 24*time.Hour), // // prevent leak
	}
	w.control = &task.Periodic{
		Execute:  w.heartbeat,
		Interval: time.Second * 2,
	}
	w.control.Start()
	return w, nil
}

func (w *PortalWorker) heartbeat() error {
	w.heartbeatMu.Lock()
	if w.heartbeatClosing {
		w.heartbeatMu.Unlock()
		return errors.New("portal worker is closing")
	}
	w.heartbeats.Add(1)
	w.heartbeatMu.Unlock()
	defer w.heartbeats.Done()
	if w.Closed() {
		return errors.New("client worker stopped")
	}

	w.mu.Lock()
	if w.draining || w.writer == nil {
		w.mu.Unlock()
		return errors.New("already disposed")
	}

	msg := &Control{}
	msg.FillInRandom()

	if w.client.TotalConnections() > 256 {
		w.draining = true
		msg.State = Control_DRAIN
	}

	w.counter = (w.counter + 1) % 5
	write := w.draining || w.counter == 1
	draining := w.draining
	writer := w.writer
	reader := w.reader
	if draining {
		w.writer = nil
	}
	w.mu.Unlock()
	if write {
		b, err := proto.Marshal(msg)
		common.Must(err)
		mb := buf.MergeBytes(nil, b)
		w.timer.Update()
		err = writer.WriteMultiBuffer(mb)
		if draining {
			common.Close(writer)
			common.Interrupt(reader)
		}
		return err
	}
	return nil
}

func (w *PortalWorker) IsFull() bool {
	return w.client.IsFull()
}

func (w *PortalWorker) Draining() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.draining
}

func (w *PortalWorker) Closed() bool {
	return w.client.Closed()
}

func (w *PortalWorker) Close() error {
	var result error
	w.closeOnce.Do(func() {
		w.heartbeatMu.Lock()
		w.heartbeatClosing = true
		w.heartbeatMu.Unlock()
		if w.timer != nil {
			w.timer.SetTimeout(0)
		}
		w.mu.Lock()
		writer, reader := w.writer, w.reader
		w.writer, w.reader = nil, nil
		w.draining = true
		w.mu.Unlock()
		// Close captured I/O before joining a heartbeat that may be blocked in it.
		result = errors.Combine(result, common.Close(writer), common.Interrupt(reader), w.client.Close())
		if w.control != nil {
			result = errors.Combine(result, w.control.Close())
		}
		w.heartbeats.Wait()
	})
	return result
}
