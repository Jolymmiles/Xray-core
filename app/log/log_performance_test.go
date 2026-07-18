package log

import (
	"testing"

	corelog "github.com/xtls/xray-core/common/log"
)

type performanceHandler struct{}

func (*performanceHandler) Handle(corelog.Message) {}

var performanceAccessMessage = &corelog.AccessMessage{From: "source", To: "target", Status: corelog.AccessAccepted}

func performanceInstance() *Instance {
	instance := &Instance{
		config:       &Config{ErrorLogLevel: corelog.Severity_Warning},
		accessLogger: new(performanceHandler),
		active:       true,
	}
	instance.publishState()
	return instance
}

func BenchmarkInstanceHandleAccess(b *testing.B) {
	instance := performanceInstance()
	b.ReportAllocs()
	for b.Loop() {
		instance.Handle(performanceAccessMessage)
	}
}

func BenchmarkInstanceHandleAccessParallel(b *testing.B) {
	instance := performanceInstance()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			instance.Handle(performanceAccessMessage)
		}
	})
}
