/*
 * bitesize - disk I/O sizes, using Linux eBPF.
 *
 * This uses eBPF to record a histogram of disk I/O sizes, in-kernel. This uses
 * current eBPF capabilities; it should be rewriten as more features are added.
 *
 * USAGE: ./bitesize [-h] [interval [count]]
 *
 * Based on eBPF sample tracex2 by Alexi Starovoitov.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * 15-Apr-2015	Brendan Gregg	Created this.
 */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <linux/bpf.h>
#include <unistd.h>
#include "libbpf.h"
#include "bpf_load.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>

#define MAX_INDEX	64
#define MAX_STARS	38

static int debug = 0;
static int interval = 5;
static int count = INT_MAX - 1;

static void usage(void)
{
	(void) printf("USAGE: bitesize [-h] [interval [count]]\n");
	(void) printf("\t\t-h\t# help (this message)\n");
	(void) printf("\t\t-v\t# verbose\n");
	exit(1);
}

static void stars(char *str, long val, long max, int width)
{
	int i;

	for (i = 0; i < (width * val / max) - 1 && i < width - 1; i++)
		str[i] = '*';
	if (val > max)
		str[i - 1] = '+';
	str[i] = '\0';
}

// workaround until/if bpf_get_current_task_info() is added
struct my_task_info {
	__u32 pid;
	__u32 uid;
	char comm[16];
};

struct hist_key {
	struct my_task_info info;
	__u32 index;
};

static void print_log2_hist_for_pid(int fd, int pid, const char *type)
{
	struct hist_key key = {}, next_key;
	char starstr[MAX_STARS];
	long value, low, high;
	long data[MAX_INDEX] = {};
	int max_ind = -1, min_ind = INT_MAX - 1;
	long max_value = 0;
	int i, ind;

	while (bpf_get_next_key(fd, &key, &next_key) == 0) {
		if (next_key.info.pid != pid) {
			key = next_key;
			continue;
		}
		bpf_lookup_elem(fd, &next_key, &value);
		ind = next_key.index;
		data[ind] += value;
		if (value && ind > max_ind)
			max_ind = ind;
		if (value && ind < min_ind)
			min_ind = ind;
		if (data[ind] > max_value)
			max_value = data[ind];
		key = next_key;
	}

	if (max_ind)
		printf("     %-15s : count     distribution\n", type);
	for (i = min_ind + 1; i <= max_ind + 1; i++) {
		stars(starstr, data[i - 1], max_value, MAX_STARS);
		low = (1l << i) >> 1;
		high = (1l << i) - 1;
		if (low == high)
			low--;
		printf("%8ld -> %-8ld : %-8ld |%-*s|\n", low, high, data[i - 1],
		       MAX_STARS, starstr);
	}
}

static void print_log2_hists(int fd, const char *type)
{
	struct hist_key key = {}, next_key;
	static struct my_task_info tasks[1024];
	int task_cnt = 0;
	int i;

	while (bpf_get_next_key(fd, &key, &next_key) == 0) {
		int found = 0;
		for (i = 0; i < task_cnt; i++)
			if (tasks[i].pid == next_key.info.pid)
				found = 1;
		if (!found)
			tasks[task_cnt++] = next_key.info;
		key = next_key;
	}

	for (i = 0; i < task_cnt; i++) {
		printf("\n  PID: %d UID: %d CMD: %s\n",
		       tasks[i].pid, tasks[i].uid, tasks[i].comm);
		print_log2_hist_for_pid(fd, tasks[i].pid, type);
	}

}

static void clear_hash(int fd)
{
	struct hist_key key = {}, next_key;

	while (bpf_get_next_key(fd, &key, &next_key) == 0) {
		bpf_delete_elem(fd, &next_key);
		key = next_key;
	}
}

// this logic should be in bpf_load.c
static void unload_bpf(void)
{
	int ret = 0;
	close(map_fd[0]);
	close(prog_fd[0]);
	close(event_fd[0]);
	/* load_bpf.c trashes kprobe_events, so we will on exit as well */
	printf("Exiting and clearing kprobes...\n");
	ret += system("> /sys/kernel/debug/tracing/kprobe_events");
}

static void int_exit(int sig)
{
	printf("\n");
	print_log2_hists(map_fd[0], "kbytes");
	unload_bpf();
	exit(0);
}

int main(int argc, char *argv[])
{
	char filename[256];
	int option, i;
	time_t now;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	/* process options */
	while ((option = getopt(argc, argv, "hv")) != -1) {
		switch (option) {
			case 'h':
			default:
				usage();
		}
	}
	argv += optind;
	if ((argc - optind) >= 1) {
		interval = atoi(*argv);
		if (interval == 0)
			usage();
			argv++;
		if ((argc - optind) >= 2)
			count = atoi(*argv);
	}

	/* load kernel program */
	if (load_bpf_file(filename)) {
		printf("ERROR: %s\n", bpf_log_buf);
		return 1;
	}

	if (debug)
		printf("%s\n", bpf_log_buf);

	signal(SIGINT, int_exit);

	printf("Tracing block device I/O... Interval %d secs.", interval);
	if (count < INT_MAX - 1)
		printf("\n");
	else
		printf(" Ctrl-C to end.\n");

	/* consume map data */
	for (i = 0; i < count; i++) {
		sleep(interval);
		if (count != 1) {
			now = time(NULL);
			printf("\n%s", ctime(&now));
		}
		print_log2_hists(map_fd[0], "kbytes");
		clear_hash(map_fd[0]);
		printf("\n");
	}

	unload_bpf();

	return 0;
}
