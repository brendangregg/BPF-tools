/*
 * bitesizes_kern.c
 *
 * Based on eBPF sample tracex2 by Alexi Starovoitov.
 * Copyright (c) 2013-2015 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * 15-Apr-2015	Brendan Gregg	Created this.
 */
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include <linux/version.h>
#include <linux/blkdev.h>

#define _(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

struct bpf_map_def SEC("maps") hist_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(long),
	.max_entries = 64,
};

static unsigned int log2(unsigned int v)
{
	unsigned int r;
	unsigned int shift;

	r = (v > 0xFFFF) << 4; v >>= r;
	shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
	shift = (v > 0xF) << 2; v >>= shift; r |= shift;
	shift = (v > 0x3) << 1; v >>= shift; r |= shift;
	r |= (v >> 1);
	return r;
}

static unsigned int log2l(unsigned long v)
{
	unsigned int hi = v >> 32;
	if (hi)
		return log2(hi) + 32;
	else
		return log2(v);
}

/* kprobe is NOT a stable ABI
 * kernel functions can be removed, renamed or completely change semantics.
 * Number of arguments and their positions can change, etc.
 * In such case this bpf+kprobe example will no longer be meaningful.
 */
SEC("kprobe/blk_start_request")
int bpf_prog1(struct pt_regs *ctx)
{
	long rq = ctx->di;
	struct request *req = (struct request *)ctx->di;
	long *value;
	u32 index = log2l(_(req->__data_len) / 1024);

	value = bpf_map_lookup_elem(&hist_map, &index);
	if (value)
		__sync_fetch_and_add(value, 1);
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
