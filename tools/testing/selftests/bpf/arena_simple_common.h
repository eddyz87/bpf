#include "bpf_arena_common.h"

struct data {
	int val;
	int __arena *ptr;
	int __arena * __arena *pptr;
};
