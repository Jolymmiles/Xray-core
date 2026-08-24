package encoding

import (
	"context"
	"net/netip"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

func remoteAddrFromContext(ctx context.Context, trusted []string) net.Addr {
	var remoteAddr net.Addr
	if pr, ok := peer.FromContext(ctx); ok {
		remoteAddr = net.EffectiveAddress(pr.Addr)
	} else {
		remoteAddr = &net.TCPAddr{
			IP:   []byte{0, 0, 0, 0},
			Port: 0,
		}
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return remoteAddr
	}

	if forwardedAddr := parseTrustedXForwardedFor(md, trusted, remoteAddr); forwardedAddr != nil && forwardedAddr.Family().IsIP() {
		remoteAddr = &net.TCPAddr{
			IP:   forwardedAddr.IP(),
			Port: 0,
		}
	}
	return remoteAddr
}

func physicalPeerFromContext(ctx context.Context) (net.Addr, bool) {
	pr, ok := peer.FromContext(ctx)
	if !ok {
		return nil, false
	}
	return net.PhysicalPeerFromAddress(pr.Addr)
}

func acceptedProxyPeerFromContext(ctx context.Context) (netip.Addr, bool) {
	pr, ok := peer.FromContext(ctx)
	if !ok {
		return netip.Addr{}, false
	}
	return net.AcceptedProxyPeerFromAddress(pr.Addr)
}

func parseTrustedXForwardedFor(md metadata.MD, trusted []string, remoteAddr net.Addr) net.Address {
	values := md.Get("X-Forwarded-For")
	if len(values) == 0 || values[0] == "" {
		return nil
	}
	value := values[0]
	for _, t := range trusted {
		if len(md.Get(t)) > 0 {
			if idx := strings.IndexByte(value, ','); idx >= 0 {
				value = value[:idx]
			}
			return net.ParseAddress(value)
		}
	}
	if len(trusted) == 0 {
		errors.LogWarning(context.Background(), `received "X-Forwarded-For" from `, remoteAddr, ` but "sockopt.trustedXForwardedFor" is not configured; ignoring it and using the real remote address`)
	} else {
		errors.LogError(context.Background(), `ignored potentially forged "X-Forwarded-For" from `, remoteAddr, `: `, value)
	}
	return nil
}

func localAddrFromContext(ctx context.Context) net.Addr {
	var localAddr net.Addr
	if pr, ok := peer.FromContext(ctx); ok {
		localAddr = pr.LocalAddr
	}
	if localAddr == nil {
		localAddr = &net.TCPAddr{
			IP:   []byte{0, 0, 0, 0},
			Port: 0,
		}
	}
	return localAddr
}
