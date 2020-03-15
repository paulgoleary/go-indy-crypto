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
import (
	"encoding/json"
	"fmt"
	"unsafe"
)

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

func (ms *MasterSecret) Free() {
	if ms.n != nil {
		C.indy_crypto_cl_master_secret_free(ms.n)
		ms.n = nil
	}
}

func (ms *MasterSecret) Value() (ret string, err error) {
	if ret, err = ms.GetJson(); err != nil {
		return
	}
	jsonMap := make(map[string]string)
	if err = json.Unmarshal([]byte(ret), &jsonMap); err != nil {
		return
	}
	maybeVal, ok := jsonMap["ms"]
	if !ok {
		err = fmt.Errorf("invalid - could not find 'ms' attribute in secret json")
	}
	return maybeVal, err
}

func (ms *MasterSecret) GetJson() (string, error) {
	var jsonCStr *C.char
	if err := withErr(C.indy_crypto_cl_master_secret_to_json(ms.n, &jsonCStr)); err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(jsonCStr))
	return C.GoString(jsonCStr), nil
}

