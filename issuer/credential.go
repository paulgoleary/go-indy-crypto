package issuer

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../libindy-crypto/target/debug -lindy_crypto
#cgo CFLAGS: -I${SRCDIR}/../../../libindy-crypto/include

#include <stdlib.h>
#include "indy_crypto.h"

extern int indy_crypto_cl_credential_schema_builder_new(void**);
extern int indy_crypto_cl_credential_schema_builder_add_attr(void*, const char*);
extern int indy_crypto_cl_credential_schema_builder_finalize(void *, void**);
extern int indy_crypto_cl_credential_schema_free(void*);

*/
import "C"
import (
	"fmt"
	"unsafe"
)

type CredSchemaBuilder struct {
	sb unsafe.Pointer
}

type CredSchema struct {
	cs unsafe.Pointer
}

// TODO: map returns codes to 'common errors' from errors/mod.rs
func withErr(ret C.int) error {
	if ret != 0 {
		return fmt.Errorf("error in indy crypto library function: %v", ret)
	}
	return nil
}

func MakeSchemaBuilder() (*CredSchemaBuilder, error) {
	ret := CredSchemaBuilder{}
	if err := withErr(C.indy_crypto_cl_credential_schema_builder_new(&ret.sb)); err != nil {
		return nil, err
	}
	return &ret, nil
}

func (sb *CredSchemaBuilder) Close() {
	if sb.sb != nil {
		C.indy_crypto_cl_credential_schema_free(sb.sb)
		sb.sb = nil
	}
}

func (sb *CredSchemaBuilder) AddAttrib(attribName string) error {
	nameCBytes := C.CBytes([]byte(attribName))
	defer C.free(nameCBytes)
	return withErr(C.indy_crypto_cl_credential_schema_builder_add_attr(sb.sb, (*C.char)(nameCBytes)))
}

func (sb *CredSchemaBuilder) Finalize() (*CredSchema, error) {
	ret := CredSchema{}
	if err := withErr(C.indy_crypto_cl_credential_schema_builder_finalize(sb.sb, &ret.cs)); err != nil {
		return nil, err
	}
	return &ret, nil
}
