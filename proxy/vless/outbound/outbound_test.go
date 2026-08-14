package outbound

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/task"
)

func TestShouldUseTestpreForOrdinaryCarrier(t *testing.T) {
	tests := []struct {
		name    string
		brutal  bool
		testpre uint32
		want    bool
	}{
		{name: "ordinary", testpre: 1, want: true},
		{name: "disabled", want: false},
		{name: "brutal", brutal: true, testpre: 1, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := shouldUseTestpre(test.brutal, test.testpre, nil); got != test.want {
				t.Fatalf("shouldUseTestpre(%t, %d, nil) = %t, want %t", test.brutal, test.testpre, got, test.want)
			}
		})
	}
}

func TestReverseCloseCancelsDelayedStart(t *testing.T) {
	executed := make(chan struct{}, 1)
	reverse := &Reverse{ctx: context.Background()}
	reverse.monitorTask = &task.Periodic{
		Execute: func() error {
			executed <- struct{}{}
			return nil
		},
		Interval: time.Hour,
	}
	reverse.scheduleStart(time.Hour)
	if err := reverse.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-executed:
		t.Fatal("closed VLESS reverse owner ran its delayed monitor start")
	default:
	}
}

func TestReverseStartRejectsAfterClose(t *testing.T) {
	reverse := &Reverse{ctx: context.Background()}
	reverse.monitorTask = &task.Periodic{
		Execute:  func() error { return nil },
		Interval: time.Hour,
	}
	if err := reverse.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reverse.Start(); err == nil {
		t.Fatal("closed VLESS reverse owner restarted its monitor")
	}
}
