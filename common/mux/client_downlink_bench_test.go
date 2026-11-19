package mux_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// countingSink is a session's output that takes everything at once.
type countingSink struct {
	frames *atomic.Int64
	done   chan struct{}
	want   int64
}

func (s *countingSink) WriteMultiBuffer(data buf.MultiBuffer) error {
	buf.ReleaseMulti(data)
	if s.frames.Add(1) == s.want {
		close(s.done)
	}
	return nil
}

// BenchmarkClientWorkerDownlink measures a client worker's downlink reader:
// frames of one full buffer each, written by the carrier's side for the
// worker's sessions in turn and delivered to outputs that never wait.
func BenchmarkClientWorkerDownlink(b *testing.B) {
	log.RegisterHandler(discardLogs{})
	b.Cleanup(func() { log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter())) })
	for _, sessions := range []int{1, 8} {
		b.Run(fmt.Sprintf("sessions=%d", sessions), func(b *testing.B) {
			uplink, uplinkWriter := pipe.New(pipe.WithSizeLimit(64 * 1024))
			downlink, downlinkWriter := pipe.New(pipe.WithSizeLimit(64 * 1024))
			worker, err := mux.NewClientWorker(transport.Link{Reader: downlink, Writer: uplinkWriter}, mux.ClientStrategy{})
			if err != nil {
				b.Fatal(err)
			}
			defer worker.Close()

			var frames atomic.Int64
			sink := &countingSink{frames: &frames, done: make(chan struct{}), want: int64(b.N)}
			ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
				Target: net.TCPDestination(net.LocalHostIP, 80),
			}})
			opened := &buf.BufferedReader{Reader: uplink}
			writers := make([]*mux.Writer, sessions)
			for i := range writers {
				upload, uploadWriter := pipe.New()
				defer uploadWriter.Close()
				if !worker.Dispatch(ctx, &transport.Link{Reader: upload, Writer: sink}) {
					b.Fatal("the worker refused a session")
				}
				// The session opens itself with an empty frame.
				var opening mux.FrameMetadata
				if err := opening.Unmarshal(opened, false); err != nil {
					b.Fatal(err)
				}
				writers[i] = mux.NewResponseWriter(opening.SessionID, downlinkWriter, protocol.TransferTypeStream)
			}

			b.SetBytes(buf.Size)
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				block := buf.New()
				block.Extend(buf.Size)
				if err := writers[i%sessions].WriteMultiBuffer(buf.MultiBuffer{block}); err != nil {
					b.Fatal(err)
				}
			}
			<-sink.done
			b.StopTimer()
		})
	}
}
