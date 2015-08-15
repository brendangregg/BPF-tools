/*
 * pidpersec.c	Count new processes (via fork).
 *		For Linux, uses BCC, eBPF. See .py file.
 *
 * 11-Aug-2015	Brendan Gregg	Created this.
 */

#include <uapi/linux/ptrace.h>

enum stat_types {
	S_COUNT = 1,
	S_MAXSTAT
};

BPF_TABLE("array", int, u64, stats, S_MAXSTAT + 1);

void stats_increment(int key) {
	u64 *leaf = stats.lookup(&key);
	if (leaf) (*leaf)++;
}

void do_count(struct pt_regs *ctx) { stats_increment(S_COUNT); }
