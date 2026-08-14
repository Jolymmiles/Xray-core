package task

import (
	"testing"
	"time"
)

func TestPeriodicCloseWaitsForCallback(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	task := &Periodic{
		Interval: time.Hour,
		Execute: func() error {
			close(started)
			<-release
			return nil
		},
	}
	startDone := make(chan error, 1)
	go func() { startDone <- task.Start() }()
	<-started

	closeDone := make(chan error, 1)
	go func() { closeDone <- task.Close() }()
	task.access.Lock()
	for !task.closing {
		task.stateChanged.Wait()
	}
	task.access.Unlock()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
		t.Fatal("periodic close returned while callback was in flight")
	default:
	}
	close(release)
	if err := <-startDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
}
