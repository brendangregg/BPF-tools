/*
 * vfscount.c	Count some VFS calls.
 *		For Linux, uses BCC, eBPF. See .py file.
 *
 * 14-Aug-2015	Brendan Gregg	Created this.
 */

#include <uapi/linux/ptrace.h>

struct key_t {
	u64 ip;
};

BPF_TABLE("hash", struct key_t, u64, counts, 256);

int do_count(struct pt_regs *ctx) {
	struct key_t key = {};
	u64 zero = 0, *val;
	key.ip = ctx->ip;
	val = counts.lookup_or_init(&key, &zero);
	(*val)++;
	return 0;
}
