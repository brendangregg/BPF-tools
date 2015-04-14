/*
 * iosnoop - basic version of iosnoop, using Linux eBPF.
 *
 * This uses eBPF to calculate disk I/O latency in-kernel. It is also a test of
 * the current eBPF capabilities; it should be rewriten as more features are
 * added.
 *
 * USAGE: ./iosnoop [-hv]
 *
 * 05-Apr-2015	Brendan Gregg	Created this.
 */

#include <stdio.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <unistd.h>
#include "libbpf.h"
#include "bpf_load.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <linux/blk_types.h>

#define DEBUGFS "/sys/kernel/debug/tracing/"
#define READBUF	(4 * 1024)

static int debug = 0;
static int verbose = 0;

static void usage(void)
{
	(void) printf("USAGE: iosnoop [-hv]\n");
	(void) printf("\t\t-h\t# help (this message)\n");
	(void) printf("\t\t-v\t# verbose\n");
	exit(1);
}

static void print_header(void)
{
	if (verbose) {
		printf("%-18s %-2s %-9s %-7s %8s\n",
		    "TIME(s)", "T", "FLAGS", "BYTES", "LAT(us)");
	} else {
		printf("%-18s %-2s %-7s %8s\n",
		    "TIME(s)", "T", "BYTES", "LAT(us)");
	}
}

static void iosnoop_pipe(void)
{
	FILE *trace_file;
	char buf[READBUF];
	char *line = buf;
	char *ptr, *time_s, *type_s, *bytes_s, *flags_s, *lat_us_s;
	unsigned long flags;

	trace_file = fopen(DEBUGFS "trace_pipe", "r");
	if (!trace_file) {
		perror("ERROR: opening trace_pipe");
		return;
	}

	while (fgets(line, sizeof (buf), trace_file)) {
		/* chomp */
		ptr = strchr(line, '\n');
		if (ptr != NULL)
			*ptr = '\0';
		if (debug)
			puts(line);

		/*
		 * read args
		 * these are a space delimitered list from _kern.c
		 */
		ptr = strrchr(line, ':');
		(void) strtok(ptr, " ");
		bytes_s = strtok(NULL, " ");
		flags_s = strtok(NULL, " ");
		lat_us_s = strtok(NULL, " ");
		flags = 0;
		if (flags_s != NULL)
			flags = strtol(flags_s, NULL, 16);
		if (flags & REQ_WRITE)	/* see blk_fill_rwbs() for logic */
			type_s = "W";
		else if (bytes_s != NULL && strcmp(bytes_s, "0") == 0)
			type_s = "M";	/* metadata */
		else
			type_s = "R";

		/*
		 * read time
		 * eg, from "... <idle>-0     [000] d.h. 13043903.874478:"
		 */
		ptr = strchr(line, ']');
		(void) strtok(ptr, " ");
		(void) strtok(NULL, " ");
		time_s = strtok(NULL, " ");
		ptr = strchr(time_s, ':');
		if (ptr != NULL)
			*ptr = '\0';

		/* output */
		if (verbose) {
			printf("%-18s %-2s %-9s %-7s %8s\n",
			    time_s, type_s, flags_s, bytes_s, lat_us_s);
		} else {
			printf("%-18s %-2s %-7s %8s\n",
			    time_s, type_s, bytes_s, lat_us_s);
		}
	}

	fclose(trace_file);
}

int main(int argc, char *argv[])
{
	char filename[256];
	int option;

	/* process options */
	while ((option = getopt(argc, argv, "hv")) != -1) {
		switch (option) {
			case 'v':
				verbose = 1;
				break;
			case 'h':
			default:
				usage();
		}
	}

	/* load kernel program */
	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (load_bpf_file(filename)) {
		printf("%s\n", bpf_log_buf);
		return 1;
	}

	if (debug)
		printf("%s\n", bpf_log_buf);

	print_header();

	/* consume trace data */
	iosnoop_pipe();

	return 0;
}
