package issuer
import "C"
import (
	go_indy_crypto "github.com/paulgoleary/go-indy-crypto"
)

func withErr(ret C.int) error {
	return go_indy_crypto.WithErr(int(ret))
}

