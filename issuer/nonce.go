package issuer

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../hyperledger/indy-crypto/libindy-crypto/target/debug -lindy_crypto
#cgo CFLAGS: -I${SRCDIR}/../../../hyperledger/indy-crypto/libindy-crypto/include

#include <stdlib.h>
#include "indy_crypto.h"

extern int indy_crypto_cl_new_nonce(void**);
extern int indy_crypto_cl_nonce_to_json(void*, const char**);
extern int indy_crypto_cl_nonce_free(void*);

*/
import "C"
import "unsafe"

type Nonce struct {
	n unsafe.Pointer
}

func MakeNonce() (*Nonce, error) {
	n := Nonce{}
	if err := withErr(C.indy_crypto_cl_new_nonce(&n.n)); err != nil {
		return nil, err
	}
	return &n, nil
}

func (n *Nonce) Close() {
	if n.n != nil {
		C.indy_crypto_cl_nonce_free(n.n)
		n.n = nil
	}
}

func (n *Nonce) GetJson() (string, error) {
	var jsonCStr *C.char
	if err := withErr(C.indy_crypto_cl_nonce_to_json(n.n, &jsonCStr)); err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(jsonCStr))
	return C.GoString(jsonCStr), nil
}