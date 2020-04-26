package go_indy_crypto

import "fmt"

// TODO: map returns codes to 'common errors' from errors/mod.rs

// CommonInvalidParam1 = 100,
// CommonInvalidParam12 = 111,

const ErrorCodeSuccess = 0
const ErrorCodeAbjectFailure = -1

func WithErr(ret int) error {
	if ret != 0 {
		if ret >= 100 && ret <= 111 {
			return fmt.Errorf("invalid param error in indy crypto library function: param ord %v", ret-100)
		}
		return fmt.Errorf("generic error in indy crypto library function: %v", ret)
	}
	return nil
}
