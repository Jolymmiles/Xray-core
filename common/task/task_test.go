package task_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/task"
)

func TestExecuteParallel(t *testing.T) {
	err := Run(context.Background(),
		func() error {
			time.Sleep(time.Millisecond * 200)
			return errors.New("test")
		}, func() error {
			time.Sleep(time.Millisecond * 500)
			return errors.New("test2")
		})

	if r := cmp.Diff(err.Error(), "test"); r != "" {
		t.Error(r)
	}
}

func TestExecuteParallelContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	err := Run(ctx, func() error {
		time.Sleep(time.Millisecond * 2000)
		return errors.New("test")
	}, func() error {
		time.Sleep(time.Millisecond * 5000)
		return errors.New("test2")
	}, func() error {
		cancel()
		return nil
	})

	errStr := err.Error()
	if !strings.Contains(errStr, "canceled") {
		t.Error("expected error string to contain 'canceled', but actually not: ", errStr)
	}
}

func BenchmarkExecuteOne(b *testing.B) {
	noop := func() error {
		return nil
	}
	for i := 0; i < b.N; i++ {
		common.Must(Run(context.Background(), noop))
	}
}

func BenchmarkExecuteTwo(b *testing.B) {
	noop := func() error {
		return nil
	}
	for i := 0; i < b.N; i++ {
		common.Must(Run(context.Background(), noop, noop))
	}
}

type benchmarkCloser struct{}

func (*benchmarkCloser) Close() error { return nil }

func BenchmarkExecuteTwoOnSuccessCloseLegacy(b *testing.B) {
	noop := func() error { return nil }
	closer := new(benchmarkCloser)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		common.Must(Run(ctx, noop, OnSuccess(noop, Close(closer))))
	}
}

func BenchmarkExecuteTwoOnSuccessClose(b *testing.B) {
	noop := func() error { return nil }
	closer := new(benchmarkCloser)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		common.Must(Run(ctx, noop, OnSuccessClose(noop, closer)))
	}
}
