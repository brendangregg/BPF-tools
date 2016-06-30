/*
 * bitesize_kern.c
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

// workaround until/if bpf_get_current_task_info() is added
struct my_task_info {
	__u32 pid;
	__u32 uid;
	char comm[16];
};

struct hist_key {
	struct my_task_info info;
	u32 index;
};

struct bpf_map_def SEC("maps") hist_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct hist_key),
	.value_size = sizeof(long),
	.max_entries = 1024,
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
 *
 * Either probe blk_start_request(), or blk_mq_start_request().
 */
SEC("kprobe/blk_mq_start_request")
int bpf_prog1(struct pt_regs *ctx)
{
	long rq = ctx->di;
	struct request *req = (struct request *)ctx->di;
	long init_val = 1;
	long *value;
	struct hist_key key = {};
	key.index = log2l(_(req->__data_len) / 1024);

	key.info.pid = bpf_get_current_pid_tgid();
	key.info.uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&key.info.comm, sizeof(key.info.comm));

	value = bpf_map_lookup_elem(&hist_map, &key);
	if (value)
		__sync_fetch_and_add(value, 1);
	else
		bpf_map_update_elem(&hist_map, &key, &init_val, BPF_ANY);
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
