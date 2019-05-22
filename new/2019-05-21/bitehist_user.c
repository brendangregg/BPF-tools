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
 * 21-May-2019	   "     "	Updated bpf helper names.
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

static void stars(char *str, long val, long max, int width)
{
	int i;

	for (i = 0; i < (width * val / max) - 1 && i < width - 1; i++)
		str[i] = '*';
	if (val > max)
		str[i - 1] = '+';
	str[i] = '\0';
}

struct hist_key {
	__u32 index;
};

static void print_log2_hist(int fd, const char *type)
{
	struct hist_key key = {}, next_key;
	char starstr[MAX_STARS];
	long value, low, high;
	long data[MAX_INDEX] = {};
	int max_ind = -1, min_ind = INT_MAX - 1;
	long max_value = 0;
	int i, ind;
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &value);
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

	if (max_ind >= 0)
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
	print_log2_hist(map_fd[0], "kbytes");
	unload_bpf();
	exit(0);
}

int main(int argc, char *argv[])
{
	char filename[256];
	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (load_bpf_file(filename)) {
		printf("ERROR: %s\n", bpf_log_buf);
		return 1;
	}
	if (debug)
		printf("%s\n", bpf_log_buf);

	signal(SIGINT, int_exit);

	printf("Tracing block I/O... Hit Ctrl-C to end.\n");
	sleep(-1);

	return 0;
}
