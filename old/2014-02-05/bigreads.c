/*
 * bigreads - trace big read() syscalls using eBPF.
 *
 * This is a simple example of extended BPF. It traces a kprobe for sys_read(),
 * which must be created beforehand, not the syscalls:sys_enter_read tracepoint
 * as it didn't work with this filter.
 *
 * USAGE:
 *	echo 'p:readprobe sys_read' > /sys/kernel/debug/tracing/kprobe_events
 *	./bpf bigreads
 *
 * This checks the requested read size, in bytes.
 *
 * 06-Jun-2014	Brendan Gregg	Created this.
 */

#include <linux/bpf.h>
#include <trace/bpf_trace.h>

#define DESC(NAME) __attribute__((section(NAME), used))
#define MIN_BYTES (1024 * 1024)

DESC("e kprobes:readprobe")
void my_filter(struct bpf_context *ctx)
{
	char fmt[] = "BIG READ: %d requested bytes\n";
	if (ctx->arg3 >= MIN_BYTES) {
		bpf_trace_printk(fmt, sizeof(fmt), (long)ctx->arg3, 0, 0);
	}
}

/* filter code license: */
char license[] DESC("license") = "GPL";
