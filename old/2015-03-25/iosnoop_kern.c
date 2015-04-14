#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include <linux/version.h>
#include <linux/blkdev.h>

#define _(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

struct bpf_map_def SEC("maps") start_ts = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(long),
	.value_size = sizeof(u64),
	.max_entries = 4096,
};

/* kprobe is NOT a stable ABI
 * kernel functions can be removed, renamed or completely change semantics.
 * Number of arguments and their positions can change, etc.
 * In such case this bpf+kprobe example will no longer be meaningful.
 */
SEC("kprobe/blk_start_request")
int bpf_prog1(struct pt_regs *ctx)
{
	long rq = ctx->di;
	u64 val = bpf_ktime_get_ns();

	bpf_map_update_elem(&start_ts, &rq, &val, BPF_ANY);
	return 0;
}

/* kprobe is NOT a stable ABI. See previous warning. */
SEC("kprobe/blk_update_request")
int bpf_prog2(struct pt_regs *ctx)
{
	long rq = ctx->di;
	struct request *req = (struct request *)ctx->di;
	u64 *value, l, base, cur_time, delta;
	u32 index;

	/* calculate latency */
	value = bpf_map_lookup_elem(&start_ts, &rq);
	if (!value)
		return 0;
	cur_time = bpf_ktime_get_ns();
	delta = cur_time - *value;
	bpf_map_delete_elem(&start_ts, &rq);

	/* using bpf_trace_printk() for DEBUG ONLY; limited to 3 args. */
	char fmt[] = "%d %x %d\n";
	bpf_trace_printk(fmt, sizeof(fmt),
	    _(req->__data_len),			/* bytes */
	    _(req->cmd_flags),			/* flags */
	    delta / 1000);			/* lat_us */

	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
