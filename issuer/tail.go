package issuer

/*
#include <stdlib.h>

extern int tail_put(void* _ctx, void* _tail);
extern int tail_take(void* _ctx, uint32_t idx, void** tail_p);

int tail_put_x(void* _ctx, void* _tail) {
	return tail_put(_ctx, _tail);
}

int tail_take_x(void* _ctx, uint32_t idx, void** tail_p) {
	return tail_take(_ctx, idx, tail_p);
}
*/
import "C"
