/* trandom-cuse — expose /dev/trandom as a real char device, backed by trandomd.
 *
 * CUSE (Character Device in Userspace) lets us register a kernel-visible
 * /dev/<name> node whose read/open/close ops run in this userspace process.
 * Any program can `open("/dev/trandom")` and read bytes like it would
 * `/dev/urandom` — we pull them from trandomd via the existing UNIX socket.
 *
 * Build: requires libfuse3 (apt install libfuse3-dev).
 * Run  : needs CAP_SYS_ADMIN to register the device (systemd unit handles this).
 */
#define FUSE_USE_VERSION 31
#include <cuse_lowlevel.h>
#include <fuse_opt.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "trandom.h"

/* Single persistent socket to trandomd, plus a mutex because CUSE dispatches
 * reads on multiple worker threads and our wire protocol is one-shot per fd. */
static int             g_sock = -1;
static uint32_t        g_lease_id = 0;
static pthread_mutex_t g_sock_mtx = PTHREAD_MUTEX_INITIALIZER;

static int connect_daemon(void) {
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	struct sockaddr_un a = { .sun_family = AF_UNIX };
	const char *path = getenv("TRANDOM_SOCK");
	if (!path) path = TRANDOM_SOCK;
	strncpy(a.sun_path, path, sizeof a.sun_path - 1);
	if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) { close(fd); return -1; }

	trandom_req_t req = { .sustained = 1 * 1024 * 1024, .burst = 4096, .flags = 0 };
	tr_msg_t m = { .op = TR_OP_LEASE_CREATE, .req = req };
	if (tr_io_write(fd, &m, sizeof m) < 0) { close(fd); return -1; }
	tr_reply_t rep;
	if (tr_io_read(fd, &rep, sizeof rep) < 0 || rep.status != 0) {
		close(fd); return -1;
	}
	g_lease_id = rep.lease_id;
	return fd;
}

/* Pull up to n bytes from trandomd through the shared socket. */
static ssize_t pull(uint8_t *buf, size_t n) {
	if (n == 0) return 0;
	if (n > 65536) n = 65536;
	pthread_mutex_lock(&g_sock_mtx);
	if (g_sock < 0) {
		g_sock = connect_daemon();
		if (g_sock < 0) { pthread_mutex_unlock(&g_sock_mtx); return -EIO; }
	}
	tr_msg_t m = { .op = TR_OP_READ, .lease_id = g_lease_id, .n = (uint32_t)n };
	if (tr_io_write(g_sock, &m, sizeof m) < 0) goto fail;
	tr_reply_t rep;
	if (tr_io_read(g_sock, &rep, sizeof rep) < 0) goto fail;
	if (rep.status != 0) { pthread_mutex_unlock(&g_sock_mtx); return rep.status; }
	if (rep.data_len == 0) { pthread_mutex_unlock(&g_sock_mtx); return 0; }
	if (tr_io_read(g_sock, buf, rep.data_len) < 0) goto fail;
	pthread_mutex_unlock(&g_sock_mtx);
	return (ssize_t)rep.data_len;
fail:
	close(g_sock);
	g_sock = -1;
	pthread_mutex_unlock(&g_sock_mtx);
	return -EIO;
}

/* ─── CUSE ops ─── */

/* Kernel creates /dev/<name> with root:root mode 0600. Relax to 0644 once
 * the device actually exists so unprivileged programs can read it. */
static void tr_init_done(void *userdata) {
	(void)userdata;
	const char *n = getenv("TRANDOM_DEVNAME");
	if (!n) n = "trandom";
	char path[128];
	snprintf(path, sizeof path, "/dev/%s", n);
	chmod(path, 0644);
}

static void tr_open(fuse_req_t req, struct fuse_file_info *fi) {
	fi->nonseekable = 1;
	fi->direct_io   = 1;
	fuse_reply_open(req, fi);
}

static void tr_read(fuse_req_t req, size_t size, off_t off,
                    struct fuse_file_info *fi) {
	(void)off; (void)fi;
	uint8_t *buf = malloc(size);
	if (!buf) { fuse_reply_err(req, ENOMEM); return; }
	ssize_t r = pull(buf, size);
	if (r < 0) { free(buf); fuse_reply_err(req, -r); return; }
	fuse_reply_buf(req, (char *)buf, (size_t)r);
	free(buf);
}

/* Reads from /dev/trandom are never writable. */
static void tr_write(fuse_req_t req, const char *buf, size_t size,
                     off_t off, struct fuse_file_info *fi) {
	(void)buf; (void)size; (void)off; (void)fi;
	fuse_reply_err(req, EPERM);
}

static const struct cuse_lowlevel_ops tr_clop = {
	.init_done = tr_init_done,
	.open      = tr_open,
	.read      = tr_read,
	.write     = tr_write,
};

int main(int argc, char **argv) {
	const char *devname = getenv("TRANDOM_DEVNAME");
	if (!devname) devname = "trandom";
	char dev_arg[256];
	snprintf(dev_arg, sizeof dev_arg, "DEVNAME=%s", devname);
	const char *dev_info_argv[] = { dev_arg };

	struct cuse_info ci = {
		.dev_info_argc = 1,
		.dev_info_argv = dev_info_argv,
		.flags         = CUSE_UNRESTRICTED_IOCTL,
	};

	/* Default: foreground, single-threaded dispatch (our socket is already
	 * serialized by g_sock_mtx anyway, and CUSE multi-threaded mode adds
	 * needless complexity for a pure byte source). */
	int new_argc = 0;
	char *new_argv[argc + 2];
	for (int i = 0; i < argc; i++) new_argv[new_argc++] = argv[i];
	new_argv[new_argc++] = (char *)"-f";
	new_argv[new_argc++] = (char *)"-s";
	new_argv[new_argc]   = NULL;

	return cuse_lowlevel_main(new_argc, new_argv, &ci, &tr_clop, NULL);
}
