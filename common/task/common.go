package task

import "github.com/xtls/xray-core/common"

// Close returns a func() that closes v.
func Close(v interface{}) func() error {
	return func() error {
		return common.Close(v)
	}
}

// OnSuccessClose closes v after f succeeds without constructing a nested
// Close closure.
func OnSuccessClose(f func() error, v interface{}) func() error {
	return func() error {
		if err := f(); err != nil {
			return err
		}
		return common.Close(v)
	}
}
