package log

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultQueueSize     = 1024
	defaultBatchSize     = 32
	defaultFlushInterval = time.Second
	defaultBlockTimeout  = time.Second
	defaultMaxRecordSize = 64 * 1024
	minimumMaxRecordSize = 1024
	maximumMaxRecordSize = 16 * 1024 * 1024
	maximumQueueSize     = 64 * 1024
	maximumBatchSize     = 4 * 1024
	maximumQueuedBytes   = 256 * 1024 * 1024
	maximumBatchBytes    = 64 * 1024 * 1024
)

// ValidateOutputBufferLimits validates one output's bounded-memory settings.
// Zero values select the same defaults used by NewRuntime.
func ValidateOutputBufferLimits(queueSize, batchSize, maxRecordSize int) error {
	if queueSize == 0 {
		queueSize = defaultQueueSize
	}
	if batchSize == 0 {
		batchSize = defaultBatchSize
	}
	if maxRecordSize == 0 {
		maxRecordSize = defaultMaxRecordSize
	}
	if queueSize < 0 {
		return errors.New("queue size is negative")
	}
	if queueSize > maximumQueueSize {
		return fmt.Errorf("queue size exceeds %d", maximumQueueSize)
	}
	if batchSize < 0 {
		return errors.New("batch size is negative")
	}
	if batchSize > maximumBatchSize {
		return fmt.Errorf("batch size exceeds %d", maximumBatchSize)
	}
	if maxRecordSize < minimumMaxRecordSize || maxRecordSize > maximumMaxRecordSize {
		return fmt.Errorf("maximum record size must be between %d and %d bytes", minimumMaxRecordSize, maximumMaxRecordSize)
	}
	if uint64(queueSize)*uint64(maxRecordSize) > maximumQueuedBytes {
		return fmt.Errorf("queue and record limits exceed %d bytes", maximumQueuedBytes)
	}
	if uint64(batchSize)*uint64(maxRecordSize) > maximumBatchBytes {
		return fmt.Errorf("batch and record limits exceed %d bytes", maximumBatchBytes)
	}
	return nil
}

// BackpressurePolicy defines what an output does when its bounded queue is
// full.
type BackpressurePolicy uint8

const (
	BackpressureDropNew BackpressurePolicy = iota
	BackpressureBlock
	BackpressureSync
)

// KindMask selects structured event families.
type KindMask uint32

// KindMaskOf returns a mask containing the supplied event families.
func KindMaskOf(kinds ...Kind) KindMask {
	var mask KindMask
	for _, kind := range kinds {
		if kind > KindUnknown && kind < 32 {
			mask |= 1 << kind
		}
	}
	return mask
}

func (m KindMask) contains(kind Kind) bool {
	return m == 0 || kind > KindUnknown && kind < 32 && m&(1<<kind) != 0
}

// OutputOptions configures one independently buffered output worker.
type OutputOptions struct {
	Name          string
	Output        Output
	Encoder       Encoder
	Kinds         KindMask
	MaxSeverity   Severity
	QueueSize     int
	BatchSize     int
	FlushInterval time.Duration
	Backpressure  BackpressurePolicy
	BlockTimeout  time.Duration
	MaxRecordSize int
}

// RuntimeOptions configures one structured logging runtime.
type RuntimeOptions struct {
	Clock             func() time.Time
	Emergency         io.Writer
	EmergencyInterval time.Duration
	Outputs           []OutputOptions
}

// OutputStats is a point-in-time snapshot of output counters.
type OutputStats struct {
	Name        string
	Accepted    uint64
	Written     uint64
	Dropped     uint64
	WriteErrors uint64
	Reconnects  uint64
	QueueDepth  int
}

// Runtime routes immutable structured events to bounded output workers.
type Runtime struct {
	clock     func() time.Time
	workers   []*outputWorker
	closeOnce sync.Once
}

// NewRuntime validates all outputs before starting their workers.
func NewRuntime(options RuntimeOptions) (*Runtime, error) {
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	runtime := &Runtime{clock: clock, workers: make([]*outputWorker, 0, len(options.Outputs))}
	emergencyInterval := options.EmergencyInterval
	if emergencyInterval == 0 {
		emergencyInterval = time.Minute
	}
	reporter := newEmergencyReporter(options.Emergency, clock, emergencyInterval)
	names := make(map[string]struct{}, len(options.Outputs))
	for index := range options.Outputs {
		outputOptions := options.Outputs[index]
		if outputOptions.Name == "" {
			return nil, fmt.Errorf("log output %d has an empty name", index)
		}
		if _, found := names[outputOptions.Name]; found {
			return nil, fmt.Errorf("duplicate log output name %q", outputOptions.Name)
		}
		names[outputOptions.Name] = struct{}{}
		if outputOptions.Output == nil {
			return nil, fmt.Errorf("log output %q is nil", outputOptions.Name)
		}
		if outputOptions.Encoder == nil {
			return nil, fmt.Errorf("log output %q encoder is nil", outputOptions.Name)
		}
		if outputOptions.QueueSize == 0 {
			outputOptions.QueueSize = defaultQueueSize
		}
		if outputOptions.BatchSize == 0 {
			outputOptions.BatchSize = defaultBatchSize
		}
		if outputOptions.FlushInterval == 0 {
			outputOptions.FlushInterval = defaultFlushInterval
		}
		if outputOptions.FlushInterval < 0 {
			return nil, fmt.Errorf("log output %q flush interval is negative", outputOptions.Name)
		}
		if outputOptions.MaxSeverity == Severity_Unknown {
			outputOptions.MaxSeverity = Severity_Debug
		}
		if outputOptions.MaxRecordSize == 0 {
			outputOptions.MaxRecordSize = defaultMaxRecordSize
		}
		if err := ValidateOutputBufferLimits(outputOptions.QueueSize, outputOptions.BatchSize, outputOptions.MaxRecordSize); err != nil {
			return nil, fmt.Errorf("log output %q: %w", outputOptions.Name, err)
		}
		if outputOptions.Backpressure == BackpressureBlock && outputOptions.BlockTimeout <= 0 {
			outputOptions.BlockTimeout = defaultBlockTimeout
		}
		if outputOptions.Backpressure > BackpressureSync {
			return nil, fmt.Errorf("log output %q has an invalid backpressure policy", outputOptions.Name)
		}
		runtime.workers = append(runtime.workers, newOutputWorker(outputOptions, reporter))
	}
	for _, worker := range runtime.workers {
		worker.start()
	}
	return runtime, nil
}

// Enabled reports whether at least one running output accepts kind and
// severity.
func (r *Runtime) Enabled(kind Kind, severity Severity) bool {
	for _, worker := range r.workers {
		if worker.enabled(kind, severity) {
			return true
		}
	}
	return false
}

// Emit snapshots the event timestamp once and offers the event to every
// matching output.
func (r *Runtime) Emit(event Event) {
	timestamped := event.hasTimestamp()
	for _, worker := range r.workers {
		if !worker.matches(event.Kind(), event.Severity()) {
			continue
		}
		if !timestamped {
			event = event.withTimestamp(r.clock())
			timestamped = true
		}
		worker.emit(event)
	}
}

// Stats returns one counter snapshot per configured output.
func (r *Runtime) Stats() []OutputStats {
	stats := make([]OutputStats, 0, len(r.workers))
	for _, worker := range r.workers {
		stats = append(stats, worker.stats())
	}
	return stats
}

// Close stops acceptance, drains accepted events, flushes every output, and
// waits until ctx expires.
func (r *Runtime) Close(ctx context.Context) error {
	r.closeOnce.Do(func() {
		for _, worker := range r.workers {
			worker.beginClose()
		}
	})
	var closeErrors []error
	for _, worker := range r.workers {
		select {
		case <-worker.done:
			if worker.closeError != nil {
				closeErrors = append(closeErrors, fmt.Errorf("log output %q: %w", worker.name, worker.closeError))
			}
		case <-ctx.Done():
			return errors.Join(append(closeErrors, ctx.Err())...)
		}
	}
	return errors.Join(closeErrors...)
}

type outputWorker struct {
	name          string
	output        Output
	encoder       Encoder
	kinds         KindMask
	maxSeverity   Severity
	queue         chan Event
	batchSize     int
	flushInterval time.Duration
	backpressure  BackpressurePolicy
	blockTimeout  time.Duration
	maxRecordSize int
	stop          chan struct{}
	done          chan struct{}
	acceptMu      sync.RWMutex
	accepting     atomic.Bool
	closeOnce     sync.Once
	closeError    error
	outputMu      sync.Mutex
	syncBuffer    []byte
	syncRecord    [1][]byte
	accepted      atomic.Uint64
	written       atomic.Uint64
	dropped       atomic.Uint64
	writeErrors   atomic.Uint64
	reporter      *emergencyReporter
}

func newOutputWorker(options OutputOptions, reporter *emergencyReporter) *outputWorker {
	worker := &outputWorker{
		name:          options.Name,
		output:        options.Output,
		encoder:       options.Encoder,
		kinds:         options.Kinds,
		maxSeverity:   options.MaxSeverity,
		queue:         make(chan Event, options.QueueSize),
		batchSize:     options.BatchSize,
		flushInterval: options.FlushInterval,
		backpressure:  options.Backpressure,
		blockTimeout:  options.BlockTimeout,
		maxRecordSize: options.MaxRecordSize,
		reporter:      reporter,
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
	worker.accepting.Store(true)
	return worker
}

func (w *outputWorker) start() { go w.run() }

func (w *outputWorker) enabled(kind Kind, severity Severity) bool {
	return w.accepting.Load() && w.matches(kind, severity)
}

func (w *outputWorker) matches(kind Kind, severity Severity) bool {
	return w.kinds.contains(kind) && severity <= w.maxSeverity
}

func (w *outputWorker) emit(event Event) {
	w.acceptMu.RLock()
	defer w.acceptMu.RUnlock()
	if !w.accepting.Load() {
		w.recordDrop()
		return
	}

	switch w.backpressure {
	case BackpressureSync:
		event = event.bounded(w.maxRecordSize)
		w.accepted.Add(1)
		w.writeSync(event)
	case BackpressureBlock:
		event = event.bounded(w.maxRecordSize)
		select {
		case w.queue <- event:
			w.accepted.Add(1)
			return
		default:
		}
		timer := time.NewTimer(w.blockTimeout)
		defer timer.Stop()
		select {
		case w.queue <- event:
			w.accepted.Add(1)
		case <-timer.C:
			w.recordDrop()
		}
	default:
		if len(w.queue) == cap(w.queue) {
			w.recordDrop()
			return
		}
		event = event.bounded(w.maxRecordSize)
		select {
		case w.queue <- event:
			w.accepted.Add(1)
		default:
			w.recordDrop()
		}
	}
}

func (w *outputWorker) beginClose() {
	w.closeOnce.Do(func() {
		w.acceptMu.Lock()
		w.accepting.Store(false)
		close(w.stop)
		w.acceptMu.Unlock()
	})
}

func (w *outputWorker) stats() OutputStats {
	var reconnects uint64
	if counter, ok := w.output.(interface{ Reconnects() uint64 }); ok {
		reconnects = counter.Reconnects()
	}
	return OutputStats{
		Name:        w.name,
		Accepted:    w.accepted.Load(),
		Written:     w.written.Load(),
		Dropped:     w.dropped.Load(),
		WriteErrors: w.writeErrors.Load(),
		Reconnects:  reconnects,
		QueueDepth:  len(w.queue),
	}
}

func (w *outputWorker) run() {
	ticker := time.NewTicker(w.flushInterval)
	defer ticker.Stop()
	defer close(w.done)

	batch := make([]Event, 0, w.batchSize)
	encoded := make([]byte, 0, w.batchSize*512)
	records := make([][]byte, 0, w.batchSize)
	for {
		select {
		case event := <-w.queue:
			batch = append(batch, event)
			batch = w.takeAvailable(batch)
			encoded, records = w.writeEvents(batch, encoded, records)
			batch = batch[:0]
		case <-ticker.C:
			w.outputMu.Lock()
			err := w.output.Flush()
			w.outputMu.Unlock()
			if err != nil {
				w.recordWriteError()
			}
		case <-w.stop:
			for {
				batch = w.takeAvailable(batch)
				if len(batch) == 0 {
					w.outputMu.Lock()
					flushError := w.output.Flush()
					closeError := w.output.Close()
					w.outputMu.Unlock()
					if flushError != nil {
						w.recordWriteError()
					}
					if closeError != nil {
						w.recordWriteError()
					}
					w.closeError = errors.Join(flushError, closeError)
					return
				}
				encoded, records = w.writeEvents(batch, encoded, records)
				batch = batch[:0]
			}
		}
	}
}

func (w *outputWorker) takeAvailable(batch []Event) []Event {
	for len(batch) < w.batchSize {
		select {
		case event := <-w.queue:
			batch = append(batch, event)
		default:
			return batch
		}
	}
	return batch
}

func (w *outputWorker) writeEvents(events []Event, encoded []byte, records [][]byte) ([]byte, [][]byte) {
	encoded = encoded[:0]
	records = records[:0]
	for _, event := range events {
		start := len(encoded)
		encoded = w.encoder.Append(encoded, event)
		records = append(records, encoded[start:])
	}
	w.outputMu.Lock()
	err := w.output.WriteBatch(records)
	w.outputMu.Unlock()
	if err != nil {
		w.recordWriteError()
	} else {
		w.written.Add(uint64(len(events)))
	}
	clear(records)
	return encoded, records
}

func (w *outputWorker) writeSync(event Event) {
	w.outputMu.Lock()
	w.syncBuffer = w.encoder.Append(w.syncBuffer[:0], event)
	w.syncRecord[0] = w.syncBuffer
	err := w.output.WriteBatch(w.syncRecord[:])
	w.syncRecord[0] = nil
	w.outputMu.Unlock()
	if err != nil {
		w.recordWriteError()
		return
	}
	w.written.Add(1)
}

func (w *outputWorker) recordDrop() {
	count := w.dropped.Add(1)
	if w.reporter != nil {
		w.reporter.report(w.name, "dropped", count)
	}
}

func (w *outputWorker) recordWriteError() {
	count := w.writeErrors.Add(1)
	if w.reporter != nil {
		w.reporter.report(w.name, "write_error", count)
	}
}

type emergencyReporter struct {
	writer   io.Writer
	clock    func() time.Time
	interval time.Duration
	mu       sync.Mutex
	last     map[string]time.Time
}

func newEmergencyReporter(writer io.Writer, clock func() time.Time, interval time.Duration) *emergencyReporter {
	if writer == nil {
		return nil
	}
	return &emergencyReporter{
		writer:   writer,
		clock:    clock,
		interval: interval,
		last:     make(map[string]time.Time),
	}
}

func (r *emergencyReporter) report(output, event string, count uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.clock()
	key := output + "\x00" + event
	if last := r.last[key]; !last.IsZero() && now.Sub(last) < r.interval {
		return
	}
	r.last[key] = now

	record := make([]byte, 0, 160)
	record = now.UTC().AppendFormat(record, consoleTimestampLayout)
	record = append(record, ` ERROR internal common/log output=`...)
	record = appendConsoleValue(record, output)
	record = append(record, ` event=`...)
	record = appendConsoleValue(record, event)
	record = append(record, ` count=`...)
	record = strconv.AppendUint(record, count, 10)
	record = append(record, '\n')
	_ = writeFull(r.writer, record)
}
