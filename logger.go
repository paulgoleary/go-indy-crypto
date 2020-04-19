package go_indy_crypto

/*
#cgo LDFLAGS: -L${SRCDIR}/../../hyperledger/indy-crypto/libindy-crypto/target/debug -lindy_crypto
#cgo CFLAGS: -I${SRCDIR}/../../hyperledger/indy-crypto/libindy-crypto/include

#include <stdlib.h>
#include "indy_crypto.h"
extern int indy_crypto_set_default_logger(const char*);
*/
import "C"
import "unsafe"

func InitEnvLogging(pattern string) {
	patternCStr := C.CString(pattern)
	defer C.free(unsafe.Pointer(patternCStr))
	C.indy_crypto_set_default_logger(patternCStr)
}
