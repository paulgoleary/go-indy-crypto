package issuer

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../hyperledger/indy-crypto/libindy-crypto/target/debug -lindy_crypto
#cgo CFLAGS: -I${SRCDIR}/../../../hyperledger/indy-crypto/libindy-crypto/include

#include <stdlib.h>
#include "indy_crypto.h"

extern int indy_crypto_cl_issuer_new_revocation_registry_def(void*, unsigned int, int, void**, void**, void**, void**);

extern int indy_crypto_cl_revocation_key_public_to_json(void*, const char**);
extern int indy_crypto_cl_revocation_key_public_free(void*);
extern int indy_crypto_cl_revocation_key_private_to_json(void*, const char**);
extern int indy_crypto_cl_revocation_key_private_free(void*);
extern int indy_crypto_cl_revocation_registry_to_json(void*, const char**);
extern int indy_crypto_cl_revocation_registry_free(void*);
extern int indy_crypto_cl_revocation_tails_generator_to_json(void*, const char**);
extern int indy_crypto_cl_revocation_tails_generator_free(void*);

*/
import "C"
import (
	"unsafe"
)

type RevocationRegDef struct {
	pk unsafe.Pointer
	sk unsafe.Pointer
	rp unsafe.Pointer
	tp unsafe.Pointer
}

func MakeRevocationRegistryDef(credDef *CredDef, maxCredNum uint, issuanceByDefault bool) (*RevocationRegDef, error) {
	regDef := RevocationRegDef{}
	var ibd C.int = 0
	if issuanceByDefault {
		ibd = 1
	}
	if err := withErr(C.indy_crypto_cl_issuer_new_revocation_registry_def(credDef.pk, C.uint(maxCredNum), ibd, &regDef.pk, &regDef.sk, &regDef.rp, &regDef.tp)); err != nil {
		return nil, err
	}
	return &regDef, nil
}

func (rrd *RevocationRegDef) Free() {
	if rrd.pk != nil {
		C.indy_crypto_cl_revocation_key_public_free(rrd.pk)
		rrd.pk = nil
	}
	if rrd.sk != nil {
		C.indy_crypto_cl_revocation_key_private_free(rrd.sk)
		rrd.sk = nil
	}
	if rrd.rp != nil {
		C.indy_crypto_cl_revocation_registry_free(rrd.rp)
		rrd.rp = nil
	}
	if rrd.tp != nil {
		C.indy_crypto_cl_revocation_tails_generator_free(rrd.tp)
		rrd.tp = nil
	}
}

func (rrd *RevocationRegDef) GetPublicKeyJson() (string, error) {
	var jsonCStr *C.char
	if err := withErr(C.indy_crypto_cl_revocation_key_public_to_json(rrd.pk, &jsonCStr)); err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(jsonCStr))
	return C.GoString(jsonCStr), nil
}

func (rrd *RevocationRegDef) GetSecretKeyJson() (string, error) {
	var jsonCStr *C.char
	if err := withErr(C.indy_crypto_cl_revocation_key_private_to_json(rrd.sk, &jsonCStr)); err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(jsonCStr))
	return C.GoString(jsonCStr), nil
}

func (rrd *RevocationRegDef) GetRevocationRegJson() (string, error) {
	var jsonCStr *C.char
	if err := withErr(C.indy_crypto_cl_revocation_registry_to_json(rrd.rp, &jsonCStr)); err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(jsonCStr))
	return C.GoString(jsonCStr), nil
}

func (rrd *RevocationRegDef) GetRevocationTailsGenJson() (string, error) {
	var jsonCStr *C.char
	if err := withErr(C.indy_crypto_cl_revocation_tails_generator_to_json(rrd.tp, &jsonCStr)); err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(jsonCStr))
	return C.GoString(jsonCStr), nil
}
