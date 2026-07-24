package inbound

import (
	"context"
	"testing"

	policyapp "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	featurepolicy "github.com/xtls/xray-core/features/policy"
)

var (
	sessionPolicySink           featurepolicy.Session
	accessDestinationSink       net.Destination
	accessDestinationStringSink string
)

func BenchmarkVLESSSessionPolicyLookup(b *testing.B) {
	manager, err := policyapp.New(context.Background(), &policyapp.Config{})
	if err != nil {
		b.Fatal(err)
	}
	handler := &Handler{sessionPolicy: manager.ForLevel(0)}
	b.ReportAllocs()
	for b.Loop() {
		sessionPolicySink = handler.sessionPolicy
	}
}

func BenchmarkVLESSAccessAndDispatchDestination(b *testing.B) {
	request := &protocol.RequestHeader{Command: protocol.RequestCommandTCP, Address: net.DomainAddress("example.com"), Port: 443}
	b.Run("repeated", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			accessDestinationStringSink = request.Destination().String()
			accessDestinationSink = request.Destination()
		}
	})
	b.Run("cached", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			destination := request.Destination()
			accessDestinationStringSink = destination.String()
			accessDestinationSink = destination
		}
	})
}
