package inbound

import (
	"bytes"
	"reflect"
	"testing"
	"unsafe"

	"github.com/xtls/xray-core/proxy/vless/encryption"
)

// BenchmarkReflectionBaseline - Baseline: reflection без кэширования
// Имитирует оригинальный процесс: TypeOf + FieldByName x2
func BenchmarkReflectionBaseline(b *testing.B) {
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		conn := &encryption.CommonConn{}
		
		// Оригинальный подход: reflection на каждой итерации
		t := reflect.TypeOf(conn).Elem()
		inputField, _ := t.FieldByName("input")
		rawInputField, _ := t.FieldByName("rawInput")
		
		p := uintptr(unsafe.Pointer(conn))
		_ = (*bytes.Reader)(unsafe.Pointer(p + inputField.Offset))
		_ = (*bytes.Buffer)(unsafe.Pointer(p + rawInputField.Offset))
	}
}

// BenchmarkReflectionOptimized - Optimized: кэшированные offsets
// Использует предварительно кэшированные offsets
func BenchmarkReflectionOptimized(b *testing.B) {
	// Подготовка: инициализировать кэш один раз
	h := &Handler{
		connTypeCache: make(map[string]reflect.Type),
		fieldOffsets:  make(map[string]map[string]uintptr),
	}
	h.cacheConnectionTypes()
	
	offsets := h.fieldOffsets["CommonConn"]
	inputOffset := offsets["input"]
	rawInputOffset := offsets["rawInput"]
	
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		conn := &encryption.CommonConn{}
		p := uintptr(unsafe.Pointer(conn))
		
		// Оптимизированный подход: просто pointer arithmetic
		_ = (*bytes.Reader)(unsafe.Pointer(p + inputOffset))
		_ = (*bytes.Buffer)(unsafe.Pointer(p + rawInputOffset))
	}
}

// BenchmarkMapLookupBaseline - Baseline: множественные lookups
func BenchmarkMapLookupBaseline(b *testing.B) {
	testMap := map[string]map[string]*Fallback{
		"test": {"a": &Fallback{}, "b": &Fallback{}},
	}
	
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		// Оригинальный подход: проверка + access
		if testMap["test"] != nil {
			a := testMap["test"]["a"]
			b := testMap["test"]["b"]
			_ = a
			_ = b
		}
	}
}

// BenchmarkMapLookupOptimized - Optimized: кэшированный lookup
func BenchmarkMapLookupOptimized(b *testing.B) {
	testMap := map[string]map[string]*Fallback{
		"test": {"a": &Fallback{}, "b": &Fallback{}},
	}
	
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		// Оптимизированный подход: один lookup, несколько accesses
		m := testMap["test"]
		if m != nil {
			a := m["a"]
			b := m["b"]
			_ = a
			_ = b
		}
	}
}

// BenchmarkPointerArithmetic - Pointer arithmetic (обе версии одинаковы)
func BenchmarkPointerArithmetic(b *testing.B) {
	conn := &encryption.CommonConn{}
	offset := uintptr(16) // Example offset
	
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		p := uintptr(unsafe.Pointer(conn))
		_ = (*bytes.Reader)(unsafe.Pointer(p + offset))
	}
}

// BenchmarkMemoryAllocations - Check memory allocations
func BenchmarkMemoryAllocations(b *testing.B) {
	b.Run("Reflection", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			conn := &encryption.CommonConn{}
			t := reflect.TypeOf(conn).Elem()
			_, _ = t.FieldByName("input")
			_, _ = t.FieldByName("rawInput")
		}
	})
	
	b.Run("Cached", func(b *testing.B) {
		h := &Handler{
			connTypeCache: make(map[string]reflect.Type),
			fieldOffsets:  make(map[string]map[string]uintptr),
		}
		h.cacheConnectionTypes()
		
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = h.fieldOffsets["CommonConn"]["input"]
			_ = h.fieldOffsets["CommonConn"]["rawInput"]
		}
	})
}

// BenchmarkConcurrentReflection - Concurrent load test
// Имитирует множество goroutines обрабатывающих connections
func BenchmarkConcurrentReflection(b *testing.B) {
	h := &Handler{
		connTypeCache: make(map[string]reflect.Type),
		fieldOffsets:  make(map[string]map[string]uintptr),
	}
	h.cacheConnectionTypes()
	
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		conn := &encryption.CommonConn{}
		offsets := h.fieldOffsets["CommonConn"]
		
		for pb.Next() {
			p := uintptr(unsafe.Pointer(conn))
			_ = (*bytes.Reader)(unsafe.Pointer(p + offsets["input"]))
			_ = (*bytes.Buffer)(unsafe.Pointer(p + offsets["rawInput"]))
		}
	})
}
