/* libtrandom — thin client for trandomd over UNIX socket.
 * Request/response protocol, thread-safe via per-handle mutex. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "trandom.h"

#define CLIENT_BUF 4096

struct trandom {
	int              fd;
	uint32_t         lease_id;
	pthread_mutex_t  mtx;
	uint8_t          buf[CLIENT_BUF];
	size_t           buf_len;
	size_t           buf_off;
};

trandom_t *trandom_request(const trandom_req_t *req) {
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) return NULL;
	struct sockaddr_un a = { .sun_family = AF_UNIX };
	const char *path = getenv("TRANDOM_SOCK");
	if (!path) path = TRANDOM_SOCK;
	strncpy(a.sun_path, path, sizeof a.sun_path - 1);
	if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) { close(fd); return NULL; }

	tr_msg_t m = { .op = TR_OP_LEASE_CREATE, .req = *req };
	if (tr_io_write(fd, &m, sizeof m) < 0) { close(fd); return NULL; }

	tr_reply_t rep;
	if (tr_io_read(fd, &rep, sizeof rep) < 0) { close(fd); errno = EIO; return NULL; }
	if (rep.status != 0) { close(fd); errno = -rep.status; return NULL; }

	trandom_t *h = calloc(1, sizeof *h);
	if (!h) { close(fd); errno = ENOMEM; return NULL; }
	h->fd = fd;
	h->lease_id = rep.lease_id;
	pthread_mutex_init(&h->mtx, NULL);
	return h;
}

/* Ask the server for up to 'n' bytes. Fills buf, returns count or -1. */
static ssize_t refill(trandom_t *h, size_t want) {
	if (want > CLIENT_BUF) want = CLIENT_BUF;
	tr_msg_t m = { .op = TR_OP_READ, .lease_id = h->lease_id, .n = (uint32_t)want };
	if (tr_io_write(h->fd, &m, sizeof m) < 0) { errno = EIO; return -1; }

	tr_reply_t rep;
	if (tr_io_read(h->fd, &rep, sizeof rep) < 0) { errno = EIO; return -1; }
	if (rep.status != 0) { errno = -rep.status; return -1; }
	if (rep.data_len > CLIENT_BUF) { errno = EPROTO; return -1; }
	if (rep.data_len && tr_io_read(h->fd, h->buf, rep.data_len) < 0) { errno = EIO; return -1; }
	h->buf_len = rep.data_len;
	h->buf_off = 0;
	return (ssize_t)rep.data_len;
}

ssize_t trandom_read(trandom_t *h, void *buf, size_t n) {
	if (!h) { errno = EINVAL; return -1; }
	pthread_mutex_lock(&h->mtx);
	if (h->buf_off == h->buf_len) {
		ssize_t r = refill(h, n);
		if (r < 0) { pthread_mutex_unlock(&h->mtx); return -1; }
		if (r == 0) { pthread_mutex_unlock(&h->mtx); errno = EAGAIN; return -1; }
	}
	size_t take = h->buf_len - h->buf_off;
	if (take > n) take = n;
	memcpy(buf, h->buf + h->buf_off, take);
	h->buf_off += take;
	pthread_mutex_unlock(&h->mtx);
	return (ssize_t)take;
}

int trandom_update(trandom_t *h, const trandom_req_t *req) {
	if (!h) return -EINVAL;
	pthread_mutex_lock(&h->mtx);
	tr_msg_t m = { .op = TR_OP_LEASE_UPDATE, .lease_id = h->lease_id, .req = *req };
	int rc = 0;
	if (tr_io_write(h->fd, &m, sizeof m) < 0) { rc = -EIO; goto out; }
	tr_reply_t rep;
	if (tr_io_read(h->fd, &rep, sizeof rep) < 0) { rc = -EIO; goto out; }
	rc = rep.status;
out:
	pthread_mutex_unlock(&h->mtx);
	return rc;
}

void trandom_release(trandom_t *h) {
	if (!h) return;
	tr_msg_t m = { .op = TR_OP_LEASE_RELEASE, .lease_id = h->lease_id };
	tr_io_write(h->fd, &m, sizeof m);
	tr_reply_t rep;
	tr_io_read(h->fd, &rep, sizeof rep);   /* best-effort */
	close(h->fd);
	pthread_mutex_destroy(&h->mtx);
	free(h);
}
