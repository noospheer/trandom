/* trctl — tiny CLI. Requests a lease and streams bytes to stdout.
 *   trctl N          — request N bytes/sec sustained, pipe to stdout
 *   trctl N | pv -r  — see current rate
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "trandom.h"

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "usage: %s <bytes/sec> [bytes-total]\n", argv[0]);
		return 2;
	}
	trandom_req_t req = {
		.sustained = (uint32_t)atoi(argv[1]),
		.burst     = 4096,
		.flags     = 0,
	};
	uint64_t total = argc > 2 ? strtoull(argv[2], NULL, 10) : 0;

	trandom_t *h = trandom_request(&req);
	if (!h) { perror("trandom_request"); return 1; }

	uint8_t buf[4096];
	uint64_t got = 0;
	while (total == 0 || got < total) {
		size_t want = sizeof buf;
		if (total && total - got < want) want = (size_t)(total - got);
		ssize_t r = trandom_read(h, buf, want);
		if (r < 0) { perror("trandom_read"); break; }
		if (write(STDOUT_FILENO, buf, (size_t)r) < 0) break;
		got += (uint64_t)r;
	}
	trandom_release(h);
	return 0;
}
