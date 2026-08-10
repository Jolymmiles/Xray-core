package outbound

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singmux"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

type smuxOutboundDialer struct {
	outbound proxy.Outbound
	dialer   internet.Dialer
	brutal   bool
}

const smuxPhysicalConnReadyTimeout = 10 * time.Second

type smuxPhysicalConnResult struct {
	conn net.Conn
	err  error
}

type smuxCarrierController struct {
	ready      chan struct{}
	carrierCtx context.Context
	waitCtx    context.Context

	readyOnce sync.Once
	mu        sync.Mutex
	result    smuxPhysicalConnResult
	terminal  bool

	setBrutal func(net.Conn, uint64) error
}

type smuxCarrierControllerContextKey struct{}

type smuxCarrierConnection struct {
	net.Conn
	controller *smuxCarrierController
}

func newSMUXCarrierController(waitCtx, carrierCtx context.Context) *smuxCarrierController {
	return &smuxCarrierController{
		ready:      make(chan struct{}),
		carrierCtx: carrierCtx,
		waitCtx:    waitCtx,
		setBrutal:  singmux.SetBrutalOptions,
	}
}

func smuxCarrierControllerFromContext(ctx context.Context) *smuxCarrierController {
	if ctx == nil {
		return nil
	}
	controller, _ := ctx.Value(smuxCarrierControllerContextKey{}).(*smuxCarrierController)
	return controller
}

// IsSMUXBrutalCarrier reports whether ctx belongs to a Brutal-enabled SMUX carrier.
func IsSMUXBrutalCarrier(ctx context.Context) bool {
	return smuxCarrierControllerFromContext(ctx) != nil
}

func (c *smuxCarrierController) publish(conn net.Conn, err error) {
	if c == nil || conn == nil && err == nil {
		return
	}
	c.mu.Lock()
	if c.terminal {
		c.mu.Unlock()
		return
	}
	if err != nil {
		c.result = smuxPhysicalConnResult{err: err}
		c.terminal = true
	} else {
		c.result = smuxPhysicalConnResult{conn: conn}
	}
	c.mu.Unlock()
	c.readyOnce.Do(func() { close(c.ready) })
}

func publishSMUXPhysicalConnection(ctx context.Context, conn net.Conn, err error) {
	if err != nil || conn == nil {
		return
	}
	if controller := smuxCarrierControllerFromContext(ctx); controller != nil {
		controller.publish(conn, nil)
	}
}

func (c *smuxCarrierController) resultSnapshot() (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.result.conn, c.result.err
}

func (c *smuxCarrierController) waitPhysicalConnection() (net.Conn, error) {
	if c == nil {
		return nil, errors.New("SMUX carrier controller is required")
	}
	timer := time.NewTimer(smuxPhysicalConnReadyTimeout)
	defer timer.Stop()
	select {
	case <-c.ready:
		return c.resultSnapshot()
	case <-c.waitCtx.Done():
		select {
		case <-c.ready:
			return c.resultSnapshot()
		default:
		}
		return nil, c.waitCtx.Err()
	case <-c.carrierCtx.Done():
		select {
		case <-c.ready:
			return c.resultSnapshot()
		default:
		}
		return nil, c.carrierCtx.Err()
	case <-timer.C:
		return nil, context.DeadlineExceeded
	}
}

func (c *smuxCarrierConnection) SetBrutal(sendBPS uint64) error {
	physical, err := c.controller.waitPhysicalConnection()
	if err != nil {
		return err
	}
	if physical == nil {
		return errors.New("SMUX physical connection is unavailable")
	}
	return c.controller.setBrutal(physical, sendBPS)
}

type cancelContextCloser struct {
	cancel context.CancelFunc
}

func (c cancelContextCloser) Close() error {
	c.cancel()
	return nil
}

func newSMUXOutboundDialer(outbound proxy.Outbound, dialer internet.Dialer, brutal bool) *smuxOutboundDialer {
	return &smuxOutboundDialer{outbound: outbound, dialer: dialer, brutal: brutal}
}

func (d *smuxOutboundDialer) DialContext(ctx context.Context, destination X.Destination) (net.Conn, error) {
	carrierCtx, cancelCarrier := context.WithCancel(context.WithoutCancel(ctx))
	var controller *smuxCarrierController
	if d.brutal {
		controller = newSMUXCarrierController(ctx, carrierCtx)
		carrierCtx = context.WithValue(carrierCtx, smuxCarrierControllerContextKey{}, controller)
	}
	parentOutbounds := session.OutboundsFromContext(ctx)
	outbounds := make([]*session.Outbound, len(parentOutbounds))
	for index, outbound := range parentOutbounds {
		if outbound == nil {
			outbounds[index] = &session.Outbound{}
			continue
		}
		clone := *outbound
		outbounds[index] = &clone
	}
	if len(outbounds) == 0 {
		outbounds = append(outbounds, &session.Outbound{})
	}
	carrierCtx = session.ContextWithOutbounds(carrierCtx, outbounds)
	outbounds[len(outbounds)-1].Target = destination

	uplinkReader, uplinkWriter := pipe.New(pipe.WithSizeLimit(64 * 1024))
	// Keep the first SMUX carrier request in its own read. Some outbound
	// protocols buffer their header and first payload in one 8 KiB buffer.
	downlinkReader, downlinkWriter := pipe.New(pipe.WithSizeLimit(0))
	conn := cnc.NewConnection(
		cnc.ConnectionInputMulti(downlinkWriter),
		cnc.ConnectionOutputMulti(uplinkReader),
		cnc.ConnectionOnClose(cancelContextCloser{cancel: cancelCarrier}),
	)
	go func() {
		if err := d.outbound.Process(carrierCtx, &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, d.dialer); err != nil {
			if controller != nil {
				controller.publish(nil, err)
			}
			if carrierCtx.Err() == nil {
				errors.LogWarningInner(carrierCtx, err, "SMUX carrier outbound stopped")
			}
		} else if controller != nil {
			controller.publish(nil, errors.New("SMUX carrier outbound stopped"))
		}
		cancelCarrier()
		common.Interrupt(downlinkReader)
		common.Close(uplinkWriter)
	}()
	if controller == nil {
		return conn, nil
	}
	return &smuxCarrierConnection{Conn: conn, controller: controller}, nil
}
