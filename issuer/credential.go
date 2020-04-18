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

extern int indy_crypto_cl_credential_values_builder_new(void**);
extern int indy_crypto_cl_credential_values_builder_add_dec_known(void*, const char*, const char*);
extern int indy_crypto_cl_credential_values_builder_add_dec_hidden(void*, const char*, const char*);
extern int indy_crypto_cl_credential_values_builder_add_dec_commitment(void*, const char*, const char*, const char*);
extern int indy_crypto_cl_credential_values_builder_finalize(void*, void**);

extern int indy_crypto_cl_credential_values_free(void*);

extern int indy_crypto_cl_prover_blind_credential_secrets(void*, void*, void*, void*, void**, void**, void**);

extern int indy_crypto_cl_blinded_credential_secrets_free(void*);
extern int indy_crypto_cl_credential_secrets_blinding_factors_free(void*);
extern int indy_crypto_cl_blinded_credential_secrets_correctness_proof_free(void*);

extern int indy_crypto_cl_blinded_credential_secrets_to_json(void*, const char**);
extern int indy_crypto_cl_credential_secrets_blinding_factors_to_json(void*, const char**);
extern int indy_crypto_cl_blinded_credential_secrets_correctness_proof_to_json(void*, const char**);

*/
import "C"
import (
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

type CredDef struct {
	pk unsafe.Pointer
	sk unsafe.Pointer
	cp unsafe.Pointer
}

type CredValuesBuilder struct {
	cb unsafe.Pointer
}

type CredValues struct {
	cv unsafe.Pointer
}

type BlindedCredSecrets struct {
	s  unsafe.Pointer
	bf unsafe.Pointer
	cp unsafe.Pointer
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
	if sb.sb == nil {
		return nil, nil
	}
	ret := CredSchema{}
	if err := withErr(C.indy_crypto_cl_credential_schema_builder_finalize(sb.sb, &ret.cs)); err != nil {
		return nil, err
	}
	sb.sb = nil // finalize free's the builder
	return &ret, nil
}

// CredSchema

func (cs *CredSchema) Free() {
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
	if sb.sb == nil {
		return nil, nil
	}
	ret := NonCredSchema{}
	if err := withErr(C.indy_crypto_cl_non_credential_schema_builder_finalize(sb.sb, &ret.cs)); err != nil {
		return nil, err
	}
	sb.sb = nil // finalize free's the builder
	return &ret, nil
}

// NonCredSchema

func (cs *NonCredSchema) Free() {
	if cs.cs != nil {
		C.indy_crypto_cl_non_credential_schema_free(cs.cs)
		cs.cs = nil
	}
}

// CredDef

func MakeCredentialDef(credSchema *CredSchema, nonCredSchema *NonCredSchema, withRevoke bool) (*CredDef, error) {
	ret := CredDef{}
	var wr C.int = 0
	if withRevoke {
		wr = 1
	}
	if err := withErr(C.indy_crypto_cl_issuer_new_credential_def(credSchema.cs, nonCredSchema.cs, wr, &ret.pk, &ret.sk, &ret.cp)); err != nil {
		return nil, err
	}
	return &ret, nil
}

func (cd *CredDef) Free() {
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

func (cd *CredDef) GetPublicKeyJson() (string, error) {
	var jsonCStr *C.char
	if err := withErr(C.indy_crypto_cl_credential_public_key_to_json(cd.pk, &jsonCStr)); err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(jsonCStr))
	return C.GoString(jsonCStr), nil
}

func (cd *CredDef) GetSecretKeyJson() (string, error) {
	var jsonCStr *C.char
	if err := withErr(C.indy_crypto_cl_credential_private_key_to_json(cd.sk, &jsonCStr)); err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(jsonCStr))
	return C.GoString(jsonCStr), nil

}

func (cd *CredDef) GetProofJson() (string, error) {
	var jsonCStr *C.char
	if err := withErr(C.indy_crypto_cl_credential_key_correctness_proof_to_json(cd.cp, &jsonCStr)); err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(jsonCStr))
	return C.GoString(jsonCStr), nil
}

// CredValuesBuilder + CredValues

func MakeCredValuesBuilder() (*CredValuesBuilder, error) {
	ret := CredValuesBuilder{}
	if err := withErr(C.indy_crypto_cl_credential_values_builder_new(&ret.cb)); err != nil {
		return nil, err
	}
	return &ret, nil
}

func (cb *CredValuesBuilder) Finalize() (*CredValues, error) {
	if cb.cb == nil {
		return nil, nil
	}
	ret := CredValues{}
	if err := withErr(C.indy_crypto_cl_credential_values_builder_finalize(cb.cb, &ret.cv)); err != nil {
		return nil, err
	}
	cb.cb = nil // finalize free's the builder
	return &ret, nil
}

func (cv *CredValues) Free() {
	if cv.cv != nil {
		C.indy_crypto_cl_credential_values_free(cv.cv)
		cv.cv = nil
	}
}

func (cb *CredValuesBuilder) AddDecKnown(attribName, attribValue string) error {
	nameCBytes := C.CBytes([]byte(attribName))
	defer C.free(nameCBytes)
	valCBytes := C.CBytes([]byte(attribValue))
	defer C.free(valCBytes)
	return withErr(C.indy_crypto_cl_credential_values_builder_add_dec_known(cb.cb, (*C.char)(nameCBytes), (*C.char)(valCBytes)))
}

func (cb *CredValuesBuilder) AddDecKnownMap(valsMap map[string]string) error {
	for attribName, attribValue := range valsMap {
		nameCBytes := C.CBytes([]byte(attribName))
		defer C.free(nameCBytes)
		valCBytes := C.CBytes([]byte(attribValue))
		defer C.free(valCBytes)
		if err := withErr(C.indy_crypto_cl_credential_values_builder_add_dec_known(cb.cb, (*C.char)(nameCBytes), (*C.char)(valCBytes))); err != nil {
			return err
		}
	}
	return nil
}

func (cb *CredValuesBuilder) AddDecHidden(attribName string, valGetter func() (string, error)) error {
	nameCBytes := C.CBytes([]byte(attribName))
	defer C.free(nameCBytes)
	attribValue, err := valGetter()
	if err != nil {
		return err
	}
	valCBytes := C.CBytes([]byte(attribValue))
	defer C.free(valCBytes)
	return withErr(C.indy_crypto_cl_credential_values_builder_add_dec_hidden(cb.cb, (*C.char)(nameCBytes), (*C.char)(valCBytes)))
}

/// Adds new hidden attribute dec_value to credential values map.
///
/// # Arguments
/// * `credential_values_builder` - Reference that contains credential values builder instance pointer.
/// * `attr` - Credential attr to add as null terminated string.
/// * `dec_value` - Credential attr dec_value. Decimal BigNum representation as null terminated string.
/// * `dec_blinding_factor` - Credential blinding factor. Decimal BigNum representation as null terminated string
func (cb *CredValuesBuilder) AddDecCommitment(attribName, decValue, decBlindingFactor string) error {
	nameCBytes := C.CBytes([]byte(attribName))
	defer C.free(nameCBytes)
	valCBytes := C.CBytes([]byte(decValue))
	defer C.free(valCBytes)
	factCBytes := C.CBytes([]byte(decBlindingFactor))
	defer C.free(factCBytes)
	return withErr(C.indy_crypto_cl_credential_values_builder_add_dec_commitment(cb.cb, (*C.char)(nameCBytes), (*C.char)(valCBytes), (*C.char)(factCBytes)))
}

// BlindedCredSecrets

/// Creates blinded credential secrets for given issuer key and master secret.
///
/// Note that blinded credential secrets deallocation must be performed by
/// calling indy_crypto_cl_blinded_credential_secrets_free.
///
/// Note that credential secrets blinding factors deallocation must be performed by
/// calling indy_crypto_cl_credential_secrets_blinding_factors_free.
///
/// Note that blinded credential secrets correctness proof deallocation must be performed by
/// calling indy_crypto_cl_blinded_credential_secrets_correctness_proof_free.
///
/// # Arguments
/// * `credential_pub_key` - Reference that contains credential public key instance pointer.
/// * `credential_key_correctness_proof` - Reference that contains credential key correctness proof instance pointer.
/// * `credential_values` - Reference that contains credential values pointer.
/// * `credential_nonce` - Reference that contains nonce instance pointer.
/// * `blinded_credential_secrets_p` - Reference that will contain blinded credential secrets instance pointer.
/// * `credential_secrets_blinding_factors_p` - Reference that will contain credential secrets blinding factors instance pointer.
/// * `blinded_credential_secrets_correctness_proof_p` - Reference that will contain blinded credential secrets correctness proof instance pointer.
func MakeBlindedCredSecrets(credDef *CredDef, credVals *CredValues, credNonce *Nonce) (*BlindedCredSecrets, error) {
	ret := BlindedCredSecrets{}
	if err := withErr(C.indy_crypto_cl_prover_blind_credential_secrets(credDef.pk, credDef.cp, credVals.cv, credNonce.n, &ret.s, &ret.bf, &ret.cp)); err != nil {
		return nil, err
	}
	return &ret, nil
}

func (bc *BlindedCredSecrets) Free() {
	if bc.s != nil {
		C.indy_crypto_cl_blinded_credential_secrets_free(bc.s)
		bc.s = nil
	}
	if bc.bf != nil {
		C.indy_crypto_cl_credential_secrets_blinding_factors_free(bc.bf)
		bc.bf = nil
	}
	if bc.cp != nil {
		C.indy_crypto_cl_blinded_credential_secrets_correctness_proof_free(bc.cp)
		bc.cp = nil
	}
}

func (bc *BlindedCredSecrets) GetSecretsJson() (string, error) {
	var jsonCStr *C.char
	if err := withErr(C.indy_crypto_cl_blinded_credential_secrets_to_json(bc.s, &jsonCStr)); err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(jsonCStr))
	return C.GoString(jsonCStr), nil
}

func (bc *BlindedCredSecrets) GetBlindingFactorsJson() (string, error) {
	var jsonCStr *C.char
	if err := withErr(C.indy_crypto_cl_credential_secrets_blinding_factors_to_json(bc.bf, &jsonCStr)); err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(jsonCStr))
	return C.GoString(jsonCStr), nil
}

func (bc *BlindedCredSecrets) GetCorrectnessProofJson() (string, error) {
	var jsonCStr *C.char
	if err := withErr(C.indy_crypto_cl_blinded_credential_secrets_correctness_proof_to_json(bc.cp, &jsonCStr)); err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(jsonCStr))
	return C.GoString(jsonCStr), nil
}