/*
 * vfsstat.c	Count some VFS calls.
 *		For Linux, uses BCC, eBPF. See .py file.
 *
 * 14-Aug-2015	Brendan Gregg	Created this.
 */

#include <uapi/linux/ptrace.h>

enum stat_types {
	S_READ = 1,
	S_WRITE,
	S_FSYNC,
	S_OPEN,
	S_CREATE,
	S_MAXSTAT
};

BPF_TABLE("array", int, u64, stats, S_MAXSTAT + 1);

void stats_increment(int key) {
	u64 *leaf = stats.lookup(&key);
	if (leaf) (*leaf)++;
}

void do_read(struct pt_regs *ctx) { stats_increment(S_READ); }
void do_write(struct pt_regs *ctx) { stats_increment(S_WRITE); }
void do_fsync(struct pt_regs *ctx) { stats_increment(S_FSYNC); }
void do_open(struct pt_regs *ctx) { stats_increment(S_OPEN); }
void do_create(struct pt_regs *ctx) { stats_increment(S_CREATE); }
