package issuer

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../hyperledger/indy-crypto/libindy-crypto/target/debug -lindy_crypto
#cgo CFLAGS: -I${SRCDIR}/../../../hyperledger/indy-crypto/libindy-crypto/include

#include <stdlib.h>
#include "indy_crypto.h"

extern int indy_crypto_cl_credential_schema_builder_new(void**);
extern int indy_crypto_cl_credential_schema_builder_add_attr(void*, const char*);
extern int indy_crypto_cl_credential_schema_builder_finalize(void *, void**);
extern int indy_crypto_cl_credential_schema_free(void*);

extern int indy_crypto_cl_non_credential_schema_builder_new(void**);
extern int indy_crypto_cl_non_credential_schema_builder_add_attr(void*, const char*);
extern int indy_crypto_cl_non_credential_schema_builder_finalize(void *, void**);
extern int indy_crypto_cl_non_credential_schema_free(void*);

extern int indy_crypto_cl_issuer_new_credential_def(void*, void*, int, void**, void**, void**);
extern int indy_crypto_cl_credential_public_key_to_json(void*, const char**);
extern int indy_crypto_cl_credential_public_key_free(void*);
extern int indy_crypto_cl_credential_private_key_to_json(void*, const char**);
extern int indy_crypto_cl_credential_private_key_free(void*);
extern int indy_crypto_cl_credential_key_correctness_proof_to_json(void*, const char**);
extern int indy_crypto_cl_credential_key_correctness_proof_free(void*);

*/
import "C"
import (
	"fmt"
	"unsafe"
)

type CredSchemaBuilder struct {
	sb unsafe.Pointer
}

type NonCredSchemaBuilder struct {
	sb unsafe.Pointer
}

type CredSchema struct {
	cs unsafe.Pointer
}

type NonCredSchema struct {
	cs unsafe.Pointer
}

type CredentialDef struct {
	pk unsafe.Pointer
	sk unsafe.Pointer
	cp unsafe.Pointer
}

// TODO: map returns codes to 'common errors' from errors/mod.rs
func withErr(ret C.int) error {
	if ret != 0 {
		return fmt.Errorf("error in indy crypto library function: %v", ret)
	}
	return nil
}

// CredSchemaBuilder

func MakeCredSchemaBuilder() (*CredSchemaBuilder, error) {
	ret := CredSchemaBuilder{}
	if err := withErr(C.indy_crypto_cl_credential_schema_builder_new(&ret.sb)); err != nil {
		return nil, err
	}
	return &ret, nil
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
	sb.sb = nil // finalize free's the builder
	return &ret, nil
}

// CredSchema

func (cs *CredSchema) Close() {
	if cs.cs != nil {
		C.indy_crypto_cl_credential_schema_free(cs.cs)
		cs.cs = nil
	}
}

// NonCredSchemaBuilder

func MakeNonCredSchemaBuilder() (*NonCredSchemaBuilder, error) {
	ret := NonCredSchemaBuilder{}
	if err := withErr(C.indy_crypto_cl_non_credential_schema_builder_new(&ret.sb)); err != nil {
		return nil, err
	}
	return &ret, nil
}

func (sb *NonCredSchemaBuilder) AddAttrib(attribName string) error {
	nameCBytes := C.CBytes([]byte(attribName))
	defer C.free(nameCBytes)
	return withErr(C.indy_crypto_cl_non_credential_schema_builder_add_attr(sb.sb, (*C.char)(nameCBytes)))
}

func (sb *NonCredSchemaBuilder) Finalize() (*NonCredSchema, error) {
	ret := NonCredSchema{}
	if err := withErr(C.indy_crypto_cl_non_credential_schema_builder_finalize(sb.sb, &ret.cs)); err != nil {
		return nil, err
	}
	sb.sb = nil // finalize free's the builder
	return &ret, nil
}

// NonCredSchema

func (cs *NonCredSchema) Close() {
	if cs.cs != nil {
		C.indy_crypto_cl_non_credential_schema_free(cs.cs)
		cs.cs = nil
	}
}

// CredentialDef

func MakeCredentialDef(credSchema *CredSchema, nonCredSchema *NonCredSchema, withRevoke bool) (*CredentialDef, error) {
	ret := CredentialDef{}
	var wr C.int = 0
	if withRevoke {
		wr = 1
	}
	if err := withErr(C.indy_crypto_cl_issuer_new_credential_def(credSchema.cs, nonCredSchema.cs, wr, &ret.pk, &ret.sk, &ret.cp)); err != nil {
		return nil, err
	}
	return &ret, nil
}

func (cd *CredentialDef) Close() {
	if cd.pk != nil {
		C.indy_crypto_cl_credential_public_key_free(cd.pk)
		cd.pk = nil
	}
	if cd.sk != nil {
		C.indy_crypto_cl_credential_private_key_free(cd.sk)
		cd.sk = nil
	}
	if cd.cp != nil {
		C.indy_crypto_cl_credential_key_correctness_proof_free(cd.cp)
		cd.cp = nil
	}
}

func (cd *CredentialDef) GetPublicKeyJson() (string, error) {
	var jsonCStr *C.char
	if err := withErr(C.indy_crypto_cl_credential_public_key_to_json(cd.pk, &jsonCStr)); err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(jsonCStr))
	return C.GoString(jsonCStr), nil
}

func (cd *CredentialDef) GetSecretKeyJson() (string, error) {
	var jsonCStr *C.char
	if err := withErr(C.indy_crypto_cl_credential_private_key_to_json(cd.sk, &jsonCStr)); err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(jsonCStr))
	return C.GoString(jsonCStr), nil

}

func (cd *CredentialDef) GetProofJson() (string, error) {
	var jsonCStr *C.char
	if err := withErr(C.indy_crypto_cl_credential_key_correctness_proof_to_json(cd.cp, &jsonCStr)); err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(jsonCStr))
	return C.GoString(jsonCStr), nil
}
