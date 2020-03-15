package go_indy_crypto

import "fmt"

// TODO: map returns codes to 'common errors' from errors/mod.rs
func WithErr(ret int) error {
	if ret != 0 {
		return fmt.Errorf("error in indy crypto library function: %v", ret)
	}
	return nil
}

