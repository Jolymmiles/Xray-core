package hysteria

import (
	"context"
	"encoding/binary"
	"math/bits"
	"math/rand"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/transport/internet"
)

const (
	closeErrCodeOK            = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeProtocolError = 0x101 // HTTP3 ErrCodeGeneralProtocolError
	URLHost                   = "hysteria"
	URLPath                   = "/auth"
	RequestHeaderAuth         = "Hysteria-Auth"
	ResponseHeaderUDPEnabled  = "Hysteria-UDP"
	CommonHeaderCCRX          = "Hysteria-CC-RX"
	CommonHeaderPadding       = "Hysteria-Padding"
	StatusAuthOK              = 233
	FrameTypeTCPRequest       = 0x401
	MaxDatagramFrameSize      = 1200
	udpMessageChanSize        = 1024
	idleCleanupInterval       = 1 * time.Second
)

const (
	paddingChars       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	paddingLookup      = paddingChars + "ab"
	paddingChunkDigits = 10
	paddingChunkMask   = uint64(1<<6 - 1)
)

var paddingPairLookup = func() [1 << 12]uint16 {
	var pairs [1 << 12]uint16
	for value := range pairs {
		pairs[value] = uint16(paddingLookup[value&int(paddingChunkMask)]) |
			uint16(paddingLookup[value>>6])<<8
	}
	return pairs
}()

type padding struct {
	Min int
	Max int
}

func (p padding) Len() int {
	return p.Min + rand.Intn(p.Max-p.Min)
}

func (padding) Fill(bs []byte) {
	fillPaddingWithState(bs, newPaddingState())
}

func newPaddingState() uint64 {
	state := rand.Uint64()
	if state == 0 {
		state = 0x9e3779b97f4a7c15
	}
	return state
}

// LenAndState returns a protocol-valid random padding length and the random
// state used to fill it, avoiding a second global RNG call.
func (p padding) LenAndState() (int, uint64) {
	state := newPaddingState()
	span := uint64(p.Max - p.Min)
	scaled, _ := bits.Mul64(state, span)
	return p.Min + int(scaled), state
}

// FillWithState fills padding from state returned by LenAndState.
func (padding) FillWithState(bs []byte, state uint64) {
	if state == 0 {
		state = 0x9e3779b97f4a7c15
	}
	fillPaddingWithState(bs, state)
}

func fillPaddingWithState(bs []byte, state uint64) {
	for len(bs) >= 2*paddingChunkDigits {
		state, value := nextPaddingValue(state)
		fillPaddingValueFull((*[paddingChunkDigits]byte)(bs), value)
		state, value = nextPaddingValue(state)
		fillPaddingValueFull((*[paddingChunkDigits]byte)(bs[paddingChunkDigits:]), value)
		bs = bs[2*paddingChunkDigits:]
	}
	for len(bs) > 0 {
		var value uint64
		state, value = nextPaddingValue(state)
		if len(bs) >= paddingChunkDigits {
			bs = bs[fillPaddingValueFull((*[paddingChunkDigits]byte)(bs), value):]
		} else {
			bs = bs[fillPaddingValue(bs, value):]
		}
	}
}

func nextPaddingValue(state uint64) (uint64, uint64) {
	state ^= state >> 12
	state ^= state << 25
	state ^= state >> 27
	return state, state * 0x2545f4914f6cdd1d
}

func fillPaddingValueFull(bs *[paddingChunkDigits]byte, value uint64) int {
	binary.LittleEndian.PutUint16(bs[0:2], paddingPairLookup[value&0xfff])
	binary.LittleEndian.PutUint16(bs[2:4], paddingPairLookup[value>>12&0xfff])
	binary.LittleEndian.PutUint16(bs[4:6], paddingPairLookup[value>>24&0xfff])
	binary.LittleEndian.PutUint16(bs[6:8], paddingPairLookup[value>>36&0xfff])
	bs[8] = paddingLookup[value>>48&paddingChunkMask]
	bs[9] = paddingLookup[value>>54&paddingChunkMask]
	return paddingChunkDigits
}

func fillPaddingValue(bs []byte, value uint64) int {
	length := min(len(bs), paddingChunkDigits)
	for index := range length {
		bs[index] = paddingLookup[value&paddingChunkMask]
		value >>= 6
	}
	return length
}

func (p padding) String() string {
	length, state := p.LenAndState()
	bs := make([]byte, length)
	p.FillWithState(bs, state)
	return string(bs)
}

var (
	AuthRequestPadding  = padding{Min: 256, Max: 2048}
	AuthResponsePadding = padding{Min: 256, Max: 2048}
	TcpRequestPadding   = padding{Min: 64, Max: 512}
	TcpResponsePadding  = padding{Min: 128, Max: 1024}
)

type datagramKey struct{}

func ContextWithDatagram(ctx context.Context, v bool) context.Context {
	return context.WithValue(ctx, datagramKey{}, v)
}

func DatagramFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(datagramKey{}).(bool)
	return v
}

type validatorKey struct{}

func ContextWithValidator(ctx context.Context, v *account.Validator) context.Context {
	return context.WithValue(ctx, validatorKey{}, v)
}

func ValidatorFromContext(ctx context.Context) *account.Validator {
	v, _ := ctx.Value(validatorKey{}).(*account.Validator)
	return v
}

type status int

const (
	StatusNull status = iota
	StatusActive
	StatusInactive
)

const protocolName = "hysteria"

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return &Config{
			UdpIdleTimeout: 60,
		}
	}))
}
