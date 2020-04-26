package issuer

/*
#include <stdlib.h>

int tail_put(void* _ctx, void* _tail);
int tail_take(void* _ctx, uint32_t idx, void** tail_p);

*/
import "C"
import (
	"fmt"
	go_indy_crypto "github.com/paulgoleary/go-indy-crypto"
	"sync"
	"unsafe"
)

type Tail struct {
	T unsafe.Pointer
}

type TailsContext struct {
	TC unsafe.Pointer
}

type SimpleTailStorage struct {
	tc    TailsContext
	tails []*Tail
}

var (
	mutex    sync.Mutex
	stsStore = map[unsafe.Pointer]*SimpleTailStorage{}
)

// inspired by https://github.com/mattn/go-pointer
func save(v *SimpleTailStorage) (unsafe.Pointer, error) {
	if v == nil {
		return nil, nil
	}

	// Generate real fake C pointer.
	// This pointer will not store any data, but will be used for indexing purposes.
	// Since Go doesn't allow to cast dangling pointer to unsafe.Pointer, we do really allocate one byte.
	// Why we need indexing, because Go doest allow C code to store pointers to Go data.
	var ptr unsafe.Pointer = C.malloc(C.size_t(1))
	if ptr == nil {
		return nil, fmt.Errorf("can't allocate 'cgo-pointer hack index pointer': ptr == nil")
	}

	mutex.Lock()
	stsStore[ptr] = v
	mutex.Unlock()

	return ptr, nil
}

func restore(ptr unsafe.Pointer) (v *SimpleTailStorage) {
	if ptr == nil {
		return nil
	}

	mutex.Lock()
	v = stsStore[ptr]
	mutex.Unlock()
	return
}

func unref(ptr unsafe.Pointer) {
	if ptr == nil {
		return
	}

	mutex.Lock()
	delete(stsStore, ptr)
	mutex.Unlock()

	C.free(ptr)
}

func MakeSimpleTailsStorage(revokeDef *RevocationRegDef) (*SimpleTailStorage, error) {

	tailsCnt, err := revokeDef.RevocationTailsCount()
	if err != nil {
		return nil, err
	}

	ret := SimpleTailStorage{}
	ret.tails = make([]*Tail, tailsCnt)
	for i := 0; i < tailsCnt; i++ {
		if ret.tails[i], err = revokeDef.RevocationTailsNext(); err != nil {
			return nil, err
		}
	}

	ret.tc.TC, err = save(&ret)
	if err != nil {
		return nil, err
	}

	return &ret, nil
}

func (sts *SimpleTailStorage) GetContext() *TailsContext {
	return &sts.tc
}

func (sts *SimpleTailStorage) Close() {
	if sts.tc.TC != nil {
		unref(sts.tc.TC)
		sts.tc.TC = nil
	}
}

//export tail_put
func tail_put(_ctx, _tail unsafe.Pointer) C.int {
	return 0
}

//export tail_take
func tail_take(_ctx unsafe.Pointer, idx C.uint32_t, tail_p *unsafe.Pointer) C.int {

	maybeSts := restore(_ctx)
	if maybeSts == nil || int(idx) >= len(maybeSts.tails) {
		return go_indy_crypto.ErrorCodeAbjectFailure
	}

	if tail_p != nil {
		*tail_p = maybeSts.tails[idx].T
	}

	return go_indy_crypto.ErrorCodeSuccess
}
