package retry // import "github.com/xtls/xray-core/common/retry"

import (
	"time"

	"github.com/xtls/xray-core/common/errors"
)

var ErrRetryFailed = errors.New("all retry attempts failed")

// Strategy is a way to retry on a specific function.
type Strategy interface {
	// On performs a retry on a specific function, until it doesn't return any error.
	On(func() error) error
}

type retryer struct {
	totalAttempt int
	nextDelay    func() uint32
}

// On implements Strategy.On.
func (r *retryer) On(method func() error) error {
	attempt := 0
	var firstError error
	var accumulatedError []error
	for attempt < r.totalAttempt {
		err := method()
		if err == nil {
			return nil
		}
		if firstError == nil {
			firstError = err
		} else if accumulatedError == nil {
			if err.Error() != firstError.Error() {
				accumulatedError = make([]error, 0, r.totalAttempt)
				accumulatedError = append(accumulatedError, firstError, err)
			}
		} else if err.Error() != accumulatedError[len(accumulatedError)-1].Error() {
			accumulatedError = append(accumulatedError, err)
		}
		delay := r.nextDelay()
		if delay != 0 {
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
		attempt++
	}
	if accumulatedError == nil && firstError != nil {
		accumulatedError = []error{firstError}
	}
	return errors.New(accumulatedError).Base(ErrRetryFailed)
}

// Timed returns a retry strategy with fixed interval.
func Timed(attempts int, delay uint32) Strategy {
	return &retryer{
		totalAttempt: attempts,
		nextDelay: func() uint32 {
			return delay
		},
	}
}

func ExponentialBackoff(attempts int, delay uint32) Strategy {
	nextDelay := uint32(0)
	return &retryer{
		totalAttempt: attempts,
		nextDelay: func() uint32 {
			r := nextDelay
			nextDelay += delay
			return r
		},
	}
}
