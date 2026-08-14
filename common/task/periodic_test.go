package task_test

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/task"
)

func TestPeriodicTaskStop(t *testing.T) {
	var value atomic.Int64
	task := &Periodic{
		Interval: time.Second * 2,
		Execute: func() error {
			value.Add(1)
			return nil
		},
	}
	common.Must(task.Start())
	time.Sleep(time.Second * 5)
	common.Must(task.Close())
	if got := value.Load(); got != 3 {
		t.Fatal("expected 3, but got ", got)
	}
	time.Sleep(time.Second * 4)
	if got := value.Load(); got != 3 {
		t.Fatal("expected 3, but got ", got)
	}
	common.Must(task.Start())
	time.Sleep(time.Second * 3)
	if got := value.Load(); got != 5 {
		t.Fatal("Expected 5, but ", got)
	}
	common.Must(task.Close())
}
