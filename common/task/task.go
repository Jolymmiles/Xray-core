package task

import (
	"context"
)

// OnSuccess executes g() after f() returns nil.
func OnSuccess(f func() error, g func() error) func() error {
	return func() error {
		if err := f(); err != nil {
			return err
		}
		return g()
	}
}

// Run executes a list of tasks in parallel, returns the first error encountered or nil if all tasks pass.
func Run(ctx context.Context, tasks ...func() error) error {
	n := len(tasks)
	if n == 1 {
		return runOne(ctx, tasks[0])
	}
	if n == 2 {
		return runTwo(ctx, tasks[0], tasks[1])
	}
	done := make(chan error, n)

	for _, task := range tasks {
		go func(f func() error) {
			done <- f()
		}(task)
	}

	/*
		if altctx := ctx.Value("altctx"); altctx != nil {
			ctx = altctx.(context.Context)
		}
	*/

	for i := 0; i < n; i++ {
		select {
		case err := <-done:
			if err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	/*
		if cancel := ctx.Value("cancel"); cancel != nil {
			cancel.(context.CancelFunc)()
		}
	*/

	return nil
}

func runOne(ctx context.Context, task func() error) error {
	done := make(chan error, 1)
	go func() { done <- task() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func runTwo(ctx context.Context, first, second func() error) error {
	done := make(chan error, 2)
	go func() { done <- first() }()
	go func() { done <- second() }()
	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
