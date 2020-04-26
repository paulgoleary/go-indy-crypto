package issuer

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../hyperledger/indy-crypto/libindy-crypto/target/debug -lindy_crypto
#cgo CFLAGS: -I${SRCDIR}/../../../hyperledger/indy-crypto/libindy-crypto/include

#include <stdlib.h>
#include "indy_crypto.h"

extern int indy_crypto_cl_witness_new(
	uint32_t,
	uint32_t,
	char,
	void*,
	void*,
	void*,
	void*,
	void**
);

extern int indy_crypto_cl_witness_free(void*);

int tail_put_x(void* _ctx, void* _tail);
int tail_take_x(void* _ctx, uint32_t idx, void** tail_p);

*/
import "C"
import "unsafe"

type Witness struct {
	w unsafe.Pointer
}

func NewWitness(sig *CredSig, tailsCxt *TailsContext) (*Witness, error) {

	maxCredNum := 5          // TODO: ???
	issuanceByDef := byte(0) // TODO: ???

	w := Witness{}
	if err := withErr(C.indy_crypto_cl_witness_new(C.uint32_t(sig.revIdx), C.uint32_t(maxCredNum), C.char(issuanceByDef),
		sig.rd, tailsCxt.TC, C.tail_take_x, C.tail_put_x, &w.w)); err != nil {
		return nil, err
	}
	return &w, nil
}

func (w *Witness) Free() {
	if w.w != nil {
		C.indy_crypto_cl_witness_free(w.w)
		w.w = nil
	}
}
