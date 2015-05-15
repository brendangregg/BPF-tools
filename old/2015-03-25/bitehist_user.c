/*
 * bitehist - disk I/O size histogram, using Linux eBPF. Global version.
 *
 * This uses eBPF to record a histogram of disk I/O sizes, in-kernel. This uses
 * current eBPF capabilities; it should be rewriten as more features are added.
 *
 * USAGE: ./bitehist [-h] [interval [count]]
 *
 * Based on eBPF sample tracex2 by Alexi Starovoitov.
 *
 * Also see bitesize, for a by-PID version that uses a hash map instead of an
 * array.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * 15-Apr-2015	Brendan Gregg	Created this.
 */

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
#include <linux/blk_types.h>

#define DEBUGFS		"/sys/kernel/debug/tracing/"
#define READBUF		(4 * 1024)
#define MAX_INDEX	64
#define MAX_STARS	38

static int debug = 0;
static int interval = 5;
static int count = INT_MAX - 1;

static void usage(void)
{
	(void) printf("USAGE: bitehist [-h] [interval [count]]\n");
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

static void print_log2_hist(int fd, const char *type)
{
	int key, i;
	long value, low, high;
	long data[MAX_INDEX] = {};
	char starstr[MAX_STARS];
	int max_ind = -1;
	long max_value = 0;

	for (key = 0; key < MAX_INDEX; key++) {
		bpf_lookup_elem(fd, &key, &value);
		data[key] = value;
		if (value && key > max_ind)
			max_ind = key;
		if (value > max_value)
			max_value = value;
	}

	if (max_ind)
		printf("     %-15s : count     distribution\n", type);
	for (i = 1; i <= max_ind + 1; i++) {
		stars(starstr, data[i - 1], max_value, MAX_STARS);
		low = (1l << i) >> 1;
		high = (1l << i) - 1;
		if (low == high)
			low--;
		printf("%8ld -> %-8ld : %-8ld |%-*s|\n", low, high, data[i - 1],
		       MAX_STARS, starstr);
	}
}

static void clear_array(int fd)
{
	int key;
	long *value = 0;

	for (key = 0; key < MAX_INDEX; key++) {
		bpf_update_elem(fd, &key, &value, BPF_ANY);
	}
}

static void int_exit(int sig)
{
	printf("\n");
	print_log2_hist(map_fd[0], "kbytes");
	exit(0);
}

int main(int argc, char *argv[])
{
	char filename[256];
	int option, i;

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
		printf("\n");
		print_log2_hist(map_fd[0], "kbytes");
		clear_array(map_fd[0]);
	}

	return 0;
}
