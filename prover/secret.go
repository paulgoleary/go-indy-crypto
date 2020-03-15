package prover

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../hyperledger/indy-crypto/libindy-crypto/target/debug -lindy_crypto
#cgo CFLAGS: -I${SRCDIR}/../../../hyperledger/indy-crypto/libindy-crypto/include

#include <stdlib.h>
#include "indy_crypto.h"

extern int indy_crypto_cl_prover_new_master_secret(void**);
extern int indy_crypto_cl_master_secret_to_json(void*, const char**);
extern int indy_crypto_cl_master_secret_free(void*);

*/
import "C"
import "unsafe"

type MasterSecret struct {
	n unsafe.Pointer
}

func MakeMasterSecret() (*MasterSecret, error) {
	n := MasterSecret{}
	if err := withErr(C.indy_crypto_cl_prover_new_master_secret(&n.n)); err != nil {
		return nil, err
	}
	return &n, nil
}

func (ms *MasterSecret) Close() {
	if ms.n != nil {
		C.indy_crypto_cl_master_secret_free(ms.n)
		ms.n = nil
	}
}

func (ms *MasterSecret) GetJson() (string, error) {
	var jsonCStr *C.char
	if err := withErr(C.indy_crypto_cl_master_secret_to_json(ms.n, &jsonCStr)); err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(jsonCStr))
	return C.GoString(jsonCStr), nil
}

