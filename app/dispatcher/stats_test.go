package dispatcher_test

import (
	"testing"

	. "github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type TestCounter int64

func (c *TestCounter) Value() int64 {
	return int64(*c)
}

func (c *TestCounter) Add(v int64) int64 {
	x := int64(*c) + v
	*c = TestCounter(x)
	return x
}

func (c *TestCounter) Set(v int64) int64 {
	*c = TestCounter(v)
	return v
}

func TestStatsWriter(t *testing.T) {
	var c TestCounter
	writer := &SizeStatWriter{
		Counter: &c,
		Writer:  buf.Discard,
	}

	mb := buf.MergeBytes(nil, []byte("abcd"))
	common.Must(writer.WriteMultiBuffer(mb))

	mb = buf.MergeBytes(nil, []byte("efg"))
	common.Must(writer.WriteMultiBuffer(mb))

	if c.Value() != 7 {
		t.Fatal("unexpected counter value. want 7, but got ", c.Value())
	}
}

func TestStatsWriterSurvivesStaleBufferRelease(t *testing.T) {
	const (
		iterations  = 64
		payloadSize = 206
	)

	var c TestCounter
	writer := &SizeStatWriter{
		Counter: &c,
		Writer:  buf.Discard,
	}
	payload := make([]byte, payloadSize)

	for range iterations {
		stale := buf.New()
		stale.Release()

		live := buf.New()
		if _, err := live.Write(payload); err != nil {
			t.Fatal(err)
		}

		stale.Release()
		common.Must(writer.WriteMultiBuffer(buf.MultiBuffer{live}))
	}

	if want := int64(iterations * payloadSize); c.Value() != want {
		t.Fatalf("counted %d bytes, want %d", c.Value(), want)
	}
}
