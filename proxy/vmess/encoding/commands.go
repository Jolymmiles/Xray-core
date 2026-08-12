package encoding

import (
	"encoding/binary"
	"io"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

var (
	ErrCommandTooLarge     = errors.New("Command too large.")
	ErrCommandTypeMismatch = errors.New("Command type mismatch.")
	ErrInvalidAuth         = errors.New("Invalid auth.")
	ErrInsufficientLength  = errors.New("Insufficient length.")
	ErrUnknownCommand      = errors.New("Unknown command.")
)

func MarshalCommand(command interface{}, writer io.Writer) error {
	if command == nil {
		return ErrUnknownCommand
	}
	return ErrUnknownCommand
}

func UnmarshalCommand(cmdID byte, data []byte) (protocol.ResponseCommand, error) {
	if len(data) <= 4 {
		return nil, ErrInsufficientLength
	}
	expectedAuth := Authenticate(data[4:])
	actualAuth := binary.BigEndian.Uint32(data[:4])
	if expectedAuth != actualAuth {
		return nil, ErrInvalidAuth
	}

	return nil, ErrUnknownCommand
}

type CommandFactory interface {
	Marshal(command interface{}, writer io.Writer) error
	Unmarshal(data []byte) (interface{}, error)
}
