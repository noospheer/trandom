/* trandom — information-theoretic entropy daemon
 * Public API for clients linking against libtrandom.
 */
#ifndef TRANDOM_H
#define TRANDOM_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>

/* Default UNIX socket path. Matches the systemd-managed install
 * (RuntimeDirectory=trandom). Override per-call with the TRANDOM_SOCK env var
 * or --sock=PATH on the daemon command line. */
#define TRANDOM_SOCK "/run/trandom/sock"

/* Lease flags */
#define TRANDOM_STRICT_IT  (1u << 0)  /* EIO instead of any fallback */
#define TRANDOM_NONBLOCK   (1u << 1)  /* trandom_read returns -EAGAIN if empty */

typedef struct trandom_req {
	uint32_t sustained;   /* target bytes/sec */
	uint32_t burst;       /* max single read, bytes */
	uint32_t flags;
	uint32_t _pad;
} trandom_req_t;

typedef struct trandom trandom_t;

/* Client API */
trandom_t *trandom_request(const trandom_req_t *req);
ssize_t    trandom_read(trandom_t *h, void *buf, size_t n);
int        trandom_update(trandom_t *h, const trandom_req_t *req);
void       trandom_release(trandom_t *h);

/* ─── Wire protocol (for custom clients) ───
 * Strictly request/response. Each exchange:
 *   client → tr_msg_t  (op + lease_id + req + n)
 *   server → tr_reply_t (status + lease_id + stats + data_len)
 *           [then data_len bytes of payload if data_len > 0]
 */
enum {
	TR_OP_LEASE_CREATE  = 1,
	TR_OP_LEASE_UPDATE  = 2,
	TR_OP_LEASE_RELEASE = 3,
	TR_OP_STATS         = 4,
	TR_OP_READ          = 5,   /* request up to msg.n bytes of entropy */
};

typedef struct tr_msg {
	uint32_t      op;
	uint32_t      lease_id;
	trandom_req_t req;
	uint32_t      n;           /* bytes requested (TR_OP_READ only) */
	uint32_t      _pad;
} tr_msg_t;

typedef struct tr_reply {
	int32_t  status;           /* 0 or -errno */
	uint32_t lease_id;
	uint32_t pool_bytes;       /* stats: current pool fill */
	uint32_t cpu_pct_x100;     /* stats: daemon CPU% × 100 */
	uint32_t data_len;         /* payload bytes following this reply */
	uint32_t sources_active;   /* bitmask: which sources are currently active */
	uint32_t sources_healthy;  /* bitmask: which sources pass health tests */
	uint32_t _pad;             /* keeps struct at an even 32-byte boundary */
} tr_reply_t;

/* Shared I/O helpers — loop read/write until n bytes transferred or EOF/error.
 * Used by both daemon and client; live here to avoid duplicating in each .c. */
static inline int tr_io_read(int fd, void *buf, size_t n) {
	unsigned char *p = buf; size_t got = 0;
	while (got < n) {
		ssize_t r = read(fd, p + got, n - got);
		if (r <= 0) return -1;
		got += (size_t)r;
	}
	return 0;
}
static inline int tr_io_write(int fd, const void *buf, size_t n) {
	const unsigned char *p = buf; size_t sent = 0;
	while (sent < n) {
		ssize_t r = write(fd, p + sent, n - sent);
		if (r <= 0) return -1;
		sent += (size_t)r;
	}
	return 0;
}

#endif
