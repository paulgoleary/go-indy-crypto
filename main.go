package main

/*
#cgo LDFLAGS: -L${SRCDIR}/../../libindy-crypto/target/debug -lindy_crypto
#cgo CFLAGS: -I${SRCDIR}/../../libindy-crypto/include

#include <stdlib.h>
#include "indy_crypto.h"

extern int indy_crypto_cl_prover_new_master_secret(void**);
extern int indy_crypto_cl_master_secret_to_json(void*, const char**);

extern int indy_crypto_cl_credential_schema_builder_new(void**);
extern int indy_crypto_cl_credential_schema_builder_add_attr(void*, const char*);

 */
import "C"
import (
	"unsafe"
)

func main() {
	var secret unsafe.Pointer
	ret := C.indy_crypto_cl_prover_new_master_secret(&secret)
	println(ret)

	var secretJsonCStr *C.char
	ret = C.indy_crypto_cl_master_secret_to_json(secret, &secretJsonCStr)
	println(ret)
	secretJsonStr := C.GoString(secretJsonCStr)
	println(secretJsonStr)

	var schemaBuilder unsafe.Pointer
	ret = C.indy_crypto_cl_credential_schema_builder_new(&schemaBuilder)
	println(ret)

	nameCBytes := C.CBytes([]byte("name"))
	defer C.free(nameCBytes)

	ret = C.indy_crypto_cl_credential_schema_builder_add_attr(schemaBuilder, (*C.char)(nameCBytes))
	println(ret)

}