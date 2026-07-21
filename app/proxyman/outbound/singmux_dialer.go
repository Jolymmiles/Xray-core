package outbound

import (
	"context"
	"net"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

type smuxOutboundDialer struct {
	outbound proxy.Outbound
	dialer   internet.Dialer
}

type cancelContextCloser struct {
	cancel context.CancelFunc
}

func (c cancelContextCloser) Close() error {
	c.cancel()
	return nil
}

func newSMUXOutboundDialer(outbound proxy.Outbound, dialer internet.Dialer) *smuxOutboundDialer {
	return &smuxOutboundDialer{outbound: outbound, dialer: dialer}
}

func (d *smuxOutboundDialer) DialContext(ctx context.Context, destination X.Destination) (net.Conn, error) {
	carrierCtx, cancelCarrier := context.WithCancel(context.WithoutCancel(ctx))
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
		if err := d.outbound.Process(carrierCtx, &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, d.dialer); err != nil && carrierCtx.Err() == nil {
			errors.LogWarningInner(carrierCtx, err, "SMUX carrier outbound stopped")
		}
		cancelCarrier()
		common.Interrupt(downlinkReader)
		common.Close(uplinkWriter)
	}()
	return conn, nil
}
