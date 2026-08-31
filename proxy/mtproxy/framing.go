package mtproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// FrameMode is the transport tag stored in the decrypted obfuscated header.
type FrameMode uint32

const (
	FrameModeAbridged           FrameMode = 0xefefefef
	FrameModeIntermediate       FrameMode = 0xeeeeeeee
	FrameModePaddedIntermediate FrameMode = 0xdddddddd
)

const (
	quickAckAbridged     = byte(0x80)
	quickAckIntermediate = uint32(1 << 31)
	abridgedExtended     = byte(0x7f)
	maxAbridgedWords     = 0xffffff
)

var errInvalidFrameMode = errors.New("mtproxy: invalid frame mode")

func (m FrameMode) String() string {
	switch m {
	case FrameModeAbridged:
		return "abridged"
	case FrameModeIntermediate:
		return "intermediate"
	case FrameModePaddedIntermediate:
		return "padded-intermediate"
	default:
		return fmt.Sprintf("frame-mode-%08x", uint32(m))
	}
}

func frameModeFromTag(tag uint32) (FrameMode, bool) {
	mode := FrameMode(tag)
	switch mode {
	case FrameModeAbridged, FrameModeIntermediate, FrameModePaddedIntermediate:
		return mode, true
	default:
		return 0, false
	}
}

// FrameHeader describes one decoded client transport frame. WireLength includes
// transport padding; PayloadLength never does.
type FrameHeader struct {
	WireLength    int
	PayloadLength int
	PaddingLength int
	HeaderLength  int
	QuickAck      bool
}

// ReadFrameHeader reads exactly one transport length prefix and validates it
// before any body allocation is made.
func ReadFrameHeader(reader io.Reader, mode FrameMode, maxPayloadLength int) (FrameHeader, error) {
	if maxPayloadLength < 4 {
		return FrameHeader{}, fmt.Errorf("mtproxy: invalid maximum payload length %d", maxPayloadLength)
	}

	switch mode {
	case FrameModeAbridged:
		return readAbridgedHeader(reader, maxPayloadLength)
	case FrameModeIntermediate, FrameModePaddedIntermediate:
		return readIntermediateHeader(reader, mode, maxPayloadLength)
	default:
		return FrameHeader{}, errInvalidFrameMode
	}
}

func readAbridgedHeader(reader io.Reader, maxPayloadLength int) (FrameHeader, error) {
	var encoded [4]byte
	if _, err := io.ReadFull(reader, encoded[:1]); err != nil {
		return FrameHeader{}, err
	}

	quickAck := encoded[0]&quickAckAbridged != 0
	lengthCode := encoded[0] &^ quickAckAbridged
	headerLength := 1
	words := uint32(lengthCode)
	if lengthCode == abridgedExtended {
		if _, err := io.ReadFull(reader, encoded[1:4]); err != nil {
			return FrameHeader{}, err
		}
		headerLength = 4
		words = uint32(encoded[1]) | uint32(encoded[2])<<8 | uint32(encoded[3])<<16
		if words < uint32(abridgedExtended) {
			return FrameHeader{}, fmt.Errorf("mtproxy: overlong abridged length %d", words)
		}
	}
	if words == 0 || words > maxAbridgedWords {
		return FrameHeader{}, fmt.Errorf("mtproxy: invalid abridged word count %d", words)
	}

	payloadLength := int(words * 4)
	if payloadLength > maxPayloadLength {
		return FrameHeader{}, fmt.Errorf("mtproxy: payload length %d exceeds maximum %d", payloadLength, maxPayloadLength)
	}
	return FrameHeader{
		WireLength:    payloadLength,
		PayloadLength: payloadLength,
		HeaderLength:  headerLength,
		QuickAck:      quickAck,
	}, nil
}

func readIntermediateHeader(reader io.Reader, mode FrameMode, maxPayloadLength int) (FrameHeader, error) {
	var encoded [4]byte
	if _, err := io.ReadFull(reader, encoded[:]); err != nil {
		return FrameHeader{}, err
	}

	value := binary.LittleEndian.Uint32(encoded[:])
	quickAck := value&quickAckIntermediate != 0
	wireLength := int(value &^ quickAckIntermediate)
	if wireLength < 4 {
		return FrameHeader{}, fmt.Errorf("mtproxy: invalid intermediate length %d", wireLength)
	}

	paddingLength := 0
	if mode == FrameModePaddedIntermediate {
		paddingLength = wireLength & 3
	} else if wireLength&3 != 0 {
		return FrameHeader{}, fmt.Errorf("mtproxy: unaligned intermediate length %d", wireLength)
	}
	payloadLength := wireLength - paddingLength
	if payloadLength < 4 {
		return FrameHeader{}, fmt.Errorf("mtproxy: empty padded payload length %d", wireLength)
	}
	if payloadLength > maxPayloadLength {
		return FrameHeader{}, fmt.Errorf("mtproxy: payload length %d exceeds maximum %d", payloadLength, maxPayloadLength)
	}

	return FrameHeader{
		WireLength:    wireLength,
		PayloadLength: payloadLength,
		PaddingLength: paddingLength,
		HeaderLength:  4,
		QuickAck:      quickAck,
	}, nil
}

// EncodeFrameHeader serializes a frame prefix. payloadLength must describe an
// MTProto payload and therefore be positive and divisible by four.
func EncodeFrameHeader(mode FrameMode, payloadLength, paddingLength int, quickAck bool) ([4]byte, int, error) {
	var result [4]byte
	if payloadLength < 4 || payloadLength&3 != 0 {
		return result, 0, fmt.Errorf("mtproxy: invalid payload length %d", payloadLength)
	}

	switch mode {
	case FrameModeAbridged:
		if paddingLength != 0 {
			return result, 0, errors.New("mtproxy: abridged frames cannot contain transport padding")
		}
		words := payloadLength / 4
		if words > maxAbridgedWords {
			return result, 0, fmt.Errorf("mtproxy: abridged payload is too large: %d", payloadLength)
		}
		quickBit := byte(0)
		if quickAck {
			quickBit = quickAckAbridged
		}
		if words <= 0x7e {
			result[0] = byte(words) | quickBit
			return result, 1, nil
		}
		result[0] = abridgedExtended | quickBit
		result[1] = byte(words)
		result[2] = byte(words >> 8)
		result[3] = byte(words >> 16)
		return result, 4, nil

	case FrameModeIntermediate:
		if paddingLength != 0 {
			return result, 0, errors.New("mtproxy: intermediate frames cannot contain transport padding")
		}

	case FrameModePaddedIntermediate:
		if paddingLength < 0 || paddingLength > 3 {
			return result, 0, fmt.Errorf("mtproxy: invalid padding length %d", paddingLength)
		}

	default:
		return result, 0, errInvalidFrameMode
	}

	wireLength := payloadLength + paddingLength
	if uint64(wireLength) >= uint64(quickAckIntermediate) {
		return result, 0, fmt.Errorf("mtproxy: intermediate payload is too large: %d", wireLength)
	}
	value := uint32(wireLength)
	if quickAck {
		value |= quickAckIntermediate
	}
	binary.LittleEndian.PutUint32(result[:], value)
	return result, 4, nil
}
