/* trandomd — IT-secure entropy daemon.
 *
 * Design:
 *   per-source threads → absorb samples into GHASH-Toeplitz accumulator
 *                      → emit 16 B to SPMC pool every MIN_ENTROPY_RATIO absorbs
 *                      → per-source NIST 800-90B health tests gate every sample
 *   scheduler thread   → every 100 ms: measure live CPU, activate/quiesce sources
 *                        to match total lease demand within --max-cpu budget
 *   socket server      → request/response protocol; one lease per connection,
 *                        LEASE_UPDATE works mid-stream because there's no stream
 *
 * Sources (each contributing to min-entropy):
 *   tsc-phc  — rdtsc vs CLOCK_TAI divergence
 *   jitter   — CPU pipeline/cache jitter via tight rdtsc loop + xorshift amplifier
 *   dram     — DRAM row-conflict latency
 *   irq-stat — /proc/interrupts snapshot hash + rdtsc (captures IRQ arrival chaos)
 *
 * x86_64 only (CLMUL required). Linux only (CLOCK_TAI, pthread, /proc).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>

#include "trandom.h"

/* ───────────────────────── Config ───────────────────────── */

#define POOL_BYTES          (256u * 1024u)
#define MIN_ENTROPY_RATIO   8                 /* raw 128-bit samples per 16 B output */
#define MAX_LEASES          256
#define SCHED_PERIOD_MS     100
#define MAX_READ_CHUNK      65536
#define IDLE_NAP_NS         (10u * 1000000u)  /* 10 ms sleep when source idle */
#define DRAM_BUF_SZ         (64u * 1024u * 1024u)
#define DRAM_STRIDE         (32u * 1024u)

/* Nanosecond helper: convert any struct timespec to uint64_t ns since epoch. */
static inline uint64_t ts_to_ns(struct timespec ts) {
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Health test parameters (NIST SP 800-90B §4.4).
 * Assumed min-entropy H=1 bit per byte → conservative cutoffs that will only
 * false-positive on near-maximally-stuck sources. */
#define RCT_CUTOFF          21           /* C = 1 + ⌈20/H⌉ */
#define APT_WINDOW          512
#define APT_CUTOFF          410

static _Atomic int g_stop;
static uint32_t    g_cpu_budget_x100 = 1000;   /* 10.00% of one vCPU */

/* ───────────────────────── Extractor ───────────────────────── */
/* GHASH over GF(2^128), irreducible poly x^128 + x^7 + x^2 + x + 1. Seeded
 * key H. Universal hash family ⇒ Leftover Hash Lemma applies.
 *
 * Per-source accumulator shards: each source has a single writer thread, so
 * no lock is needed for its own shard. Sources emit independently to the
 * pool. LHL applies per-source; the pool ends up with independent near-
 * uniform 16-byte blocks interleaved in time. */

static __m128i g_H;   /* shared extractor key — set once at startup, read-only */

static inline __m128i gf128_mul(__m128i a, __m128i b) {
	__m128i t0 = _mm_clmulepi64_si128(a, b, 0x00);
	__m128i t3 = _mm_clmulepi64_si128(a, b, 0x11);
	__m128i t1 = _mm_clmulepi64_si128(a, b, 0x10);
	__m128i t2 = _mm_clmulepi64_si128(a, b, 0x01);
	__m128i mid = _mm_xor_si128(t1, t2);
	t0 = _mm_xor_si128(t0, _mm_slli_si128(mid, 8));
	t3 = _mm_xor_si128(t3, _mm_srli_si128(mid, 8));
	__m128i poly = _mm_set_epi64x(0, 0x87);
	__m128i r = _mm_clmulepi64_si128(t3, poly, 0x01);
	t0 = _mm_xor_si128(t0, _mm_slli_si128(r, 8));
	__m128i hi = _mm_xor_si128(_mm_srli_si128(t3, 8), _mm_srli_si128(r, 8));
	__m128i r2 = _mm_clmulepi64_si128(hi, poly, 0x00);
	return _mm_xor_si128(t0, r2);
}

/* ───────────────────────── Health tests ───────────────────────── */

typedef struct health {
	uint8_t          rct_last;
	uint16_t         rct_count;
	uint8_t          apt_ref;
	uint16_t         apt_idx;
	uint16_t         apt_count;
	_Atomic int      failed;
} health_t;

/* Feed one byte of noise. Returns 0 ok, -1 on test failure (also flips failed flag). */
static int health_feed(health_t *h, uint8_t b) {
	if (atomic_load_explicit(&h->failed, memory_order_relaxed)) return -1;

	/* Repetition Count Test */
	if (b == h->rct_last) {
		if (++h->rct_count >= RCT_CUTOFF) {
			atomic_store(&h->failed, 1);
			return -1;
		}
	} else {
		h->rct_last = b;
		h->rct_count = 1;
	}

	/* Adaptive Proportion Test */
	if (h->apt_idx == 0) {
		h->apt_ref = b;
		h->apt_count = 1;
	} else {
		if (b == h->apt_ref) {
			if (++h->apt_count >= APT_CUTOFF) {
				atomic_store(&h->failed, 1);
				return -1;
			}
		}
	}
	if (++h->apt_idx >= APT_WINDOW) h->apt_idx = 0;
	return 0;
}

/* ───────────────────────── Pool (SPMC ring) ───────────────────────── */

static uint8_t                g_pool[POOL_BYTES];
static _Atomic uint64_t       g_pool_w;
static _Atomic uint64_t       g_pool_r;
static pthread_mutex_t        g_pool_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t         g_pool_cv  = PTHREAD_COND_INITIALIZER;

/* memcpy into/out of the ring, splitting at the wrap. POOL_BYTES is a power
 * of two so `& (POOL_BYTES - 1)` replaces modulo. The byte-at-a-time loop
 * this replaced was ~16× slower and held the pool mutex during the copy. */
static void pool_push(const uint8_t *src, size_t n) {
	pthread_mutex_lock(&g_pool_mtx);
	uint64_t w = atomic_load(&g_pool_w);
	uint64_t r = atomic_load(&g_pool_r);
	if (w - r + n > POOL_BYTES) atomic_store(&g_pool_r, w - POOL_BYTES + n);
	size_t off = w & (POOL_BYTES - 1);
	size_t first = POOL_BYTES - off;
	if (first >= n) {
		memcpy(g_pool + off, src, n);
	} else {
		memcpy(g_pool + off, src, first);
		memcpy(g_pool,       src + first, n - first);
	}
	atomic_store(&g_pool_w, w + n);
	pthread_cond_signal(&g_pool_cv);   /* one consumer per push — no thundering herd */
	pthread_mutex_unlock(&g_pool_mtx);
}

static size_t pool_pull(uint8_t *dst, size_t n, int blocking) {
	pthread_mutex_lock(&g_pool_mtx);
	while (blocking && !atomic_load(&g_stop)) {
		uint64_t avail = atomic_load(&g_pool_w) - atomic_load(&g_pool_r);
		if (avail) break;
		pthread_cond_wait(&g_pool_cv, &g_pool_mtx);
	}
	uint64_t w = atomic_load(&g_pool_w);
	uint64_t r = atomic_load(&g_pool_r);
	size_t avail = (size_t)(w - r);
	size_t take = n < avail ? n : avail;
	size_t off = r & (POOL_BYTES - 1);
	size_t first = POOL_BYTES - off;
	if (first >= take) {
		memcpy(dst, g_pool + off, take);
	} else {
		memcpy(dst,         g_pool + off, first);
		memcpy(dst + first, g_pool,       take - first);
	}
	atomic_store(&g_pool_r, r + take);
	pthread_mutex_unlock(&g_pool_mtx);
	return take;
}

static uint32_t pool_fill(void) {
	return (uint32_t)(atomic_load(&g_pool_w) - atomic_load(&g_pool_r));
}

/* ───────────────────────── Sources ───────────────────────── */

struct src;
typedef void (*src_loop_fn)(struct src *);

#define SRC_EMIT_BATCH   256u           /* bytes buffered per source before pool push */

typedef struct src {
	const char *name;
	src_loop_fn loop;
	void       *state;
	uint32_t    cost_pct_x100;    /* static estimate, fallback when live cpu unknown */
	uint32_t    yield_bps;        /* natural cap on bytes/sec this source can do */
	uint32_t    bytes_per_iter;   /* approx output bytes per loop iteration */
	_Atomic int enabled;          /* operator toggle */
	_Atomic int active;           /* scheduler toggle */
	_Atomic uint32_t target_bps;  /* scheduler-assigned share; 0 = idle trickle */
	health_t    health;
	pthread_t   thr;
	uint8_t     idx;              /* 0..7, for source_active/healthy bitmask */
	__m128i     acc;              /* per-source extractor shard (single-writer) */
	uint64_t    absorb_count;     /* per-source counter, only that source writes */
	uint8_t     emit_buf[SRC_EMIT_BATCH];
	uint32_t    emit_off;         /* bytes currently queued in emit_buf */
	int         raw_fd;           /* debug: raw pre-extractor byte dump, -1 if off */
} src_t;

/* Linux nanosleep resolution is ~50 µs, so naps shorter than ~500 µs are
 * unreliable. Sources batch multiple absorbs per iteration when target rate
 * would require a sub-reliable nap, keeping the sleep in the ms range while
 * yielding the requested rate. This gives clean linear CPU↔rate scaling. */
#define SRC_MIN_NAP_NS   500000u          /* 0.5 ms — lower bound of reliable sleep */
#define SRC_MAX_BATCH    1024u

/* How many absorbs to do in this loop iteration before sleeping. */
static uint32_t src_batch(const src_t *s) {
	uint32_t t = atomic_load_explicit(&s->target_bps, memory_order_relaxed);
	if (t == 0) return 1;
	uint64_t per = (uint64_t)1000000000ULL * s->bytes_per_iter / t;
	if (per == 0) return SRC_MAX_BATCH;          /* target way above source yield */
	if (per >= SRC_MIN_NAP_NS) return 1;          /* slow: one absorb then sleep */
	uint32_t b = (uint32_t)(SRC_MIN_NAP_NS / per);
	if (b < 1) b = 1;
	if (b > SRC_MAX_BATCH) b = SRC_MAX_BATCH;
	return b;
}

/* Sleep after having done `batch` absorbs, matching the target rate. A short
 * enough nap (below nanosleep's ~50 µs resolution) is skipped and the source
 * effectively runs flat-out — CPU scales with demand as a natural consequence. */
static void src_nap(const src_t *s, uint32_t batch) {
	uint32_t t = atomic_load_explicit(&s->target_bps, memory_order_relaxed);
	if (t == 0) {
		struct timespec ts = {0, IDLE_NAP_NS};
		nanosleep(&ts, NULL);
		return;
	}
	uint64_t nap = (uint64_t)1000000000ULL * s->bytes_per_iter * batch / t;
	if (nap < 50000) return;
	if (nap > 100000000ULL) nap = 100000000ULL;
	struct timespec ts = { (time_t)(nap / 1000000000ULL),
	                       (long)(nap % 1000000000ULL) };
	nanosleep(&ts, NULL);
}

/* Forward */
static void absorb(src_t *s, __m128i sample);

static void *src_thread(void *arg) {
	src_t *s = arg;
	pthread_setname_np(pthread_self(), s->name);
	while (!atomic_load(&g_stop)) {
		int on = atomic_load(&s->enabled) && atomic_load(&s->active)
		      && !atomic_load(&s->health.failed);
		if (!on) {
			struct timespec ts = {0, IDLE_NAP_NS};
			nanosleep(&ts, NULL);
			continue;
		}
		s->loop(s);
	}
	return NULL;
}

/* jitter: pipeline/cache/branch-predictor timing jitter */
static void src_jitter_loop(src_t *s) {
	volatile uint64_t x = __rdtsc();
	while (atomic_load(&s->active) && !atomic_load(&g_stop)
	    && !atomic_load(&s->health.failed)) {
		uint32_t batch = src_batch(s);
		for (uint32_t b = 0; b < batch; b++) {
			uint64_t t0 = __rdtsc();
			for (int i = 0; i < 64; i++) {
				x ^= (x << 13); x ^= (x >> 7); x ^= (x << 17);
				x += __rdtsc();
			}
			uint64_t t1 = __rdtsc();
			absorb(s, _mm_set_epi64x((int64_t)x, (int64_t)(t1 - t0)));
		}
		src_nap(s, batch);
	}
}

/* tsc-phc: rdtsc vs CLOCK_TAI divergence */
static void src_tscphc_loop(src_t *s) {
	struct timespec ts;
	while (atomic_load(&s->active) && !atomic_load(&g_stop)
	    && !atomic_load(&s->health.failed)) {
		uint32_t batch = src_batch(s);
		for (uint32_t b = 0; b < batch; b++) {
			uint64_t tsc = __rdtsc();
			clock_gettime(CLOCK_TAI, &ts);
			uint64_t phc = ts_to_ns(ts);
			absorb(s, _mm_set_epi64x((int64_t)tsc, (int64_t)(phc - tsc)));
		}
		src_nap(s, batch);
	}
}

/* dram: row-conflict latency prober */
static void src_dram_loop(src_t *s) {
	uint8_t *arr = s->state;
	if (!arr) return;
	while (atomic_load(&s->active) && !atomic_load(&g_stop)
	    && !atomic_load(&s->health.failed)) {
		uint32_t batch = src_batch(s);
		for (uint32_t b = 0; b < batch; b++) {
			uint64_t t0 = __rdtsc();
			volatile uint8_t v = 0;
			for (int i = 0; i < 16; i++)
				v ^= arr[((i * 2654435761u) * DRAM_STRIDE) % DRAM_BUF_SZ];
			uint64_t dt = __rdtsc() - t0;
			/* Low 64 bits carry the variable signal (dt); v is deterministic. */
			absorb(s, _mm_set_epi64x((int64_t)v, (int64_t)dt));
		}
		src_nap(s, batch);
	}
}

/* irq-stat: hash /proc/interrupts content XOR rdtsc, periodically.
 * Captures interrupt-arrival chaos, hypervisor IPI behavior, virtio IRQs,
 * timer firing timing. Independent of the other three sources.
 *
 * The batch iteration hashes each /proc/interrupts snapshot with a fresh
 * rdtsc — two consecutive reads typically return bit-identical content except
 * for counters that increment with IRQs, so the TSC mix carries the entropy. */
static void src_irqstat_loop(src_t *s) {
	int fd = open("/proc/interrupts", O_RDONLY);
	if (fd < 0) { atomic_store(&s->health.failed, 1); return; }
	uint8_t buf[8192];
	while (atomic_load(&s->active) && !atomic_load(&g_stop)
	    && !atomic_load(&s->health.failed)) {
		uint32_t batch = src_batch(s);
		for (uint32_t b = 0; b < batch; b++) {
			ssize_t r = pread(fd, buf, sizeof buf, 0);
			if (r <= 0) { atomic_store(&s->health.failed, 1); goto done; }
			uint64_t tsc = __rdtsc();
			for (ssize_t i = 0; i + 16 <= r; i += 16) {
				__m128i block = _mm_loadu_si128((const __m128i *)(buf + i));
				__m128i ts    = _mm_set_epi64x((int64_t)tsc,
				                               (int64_t)(tsc + (uint64_t)i));
				absorb(s, _mm_xor_si128(block, ts));
			}
		}
		src_nap(s, batch);
	}
done:
	close(fd);
}

/* Source registry. idx is the bit position in reply sources_active/healthy
 * bitmasks. cost_pct_x100 is the natural cost when running full-tilt; the
 * scheduler assigns target_bps at runtime and src_nap paces to it. */
static src_t g_sources[] = {
	{ .name="tsc-phc",  .loop=src_tscphc_loop,  .cost_pct_x100=   400,
	  .yield_bps= 500u*1024u,              .bytes_per_iter=  2, .enabled=1, .idx=0 },
	{ .name="jitter",   .loop=src_jitter_loop,  .cost_pct_x100= 14000,
	  .yield_bps=   2u*1024u*1024u,        .bytes_per_iter=  2, .enabled=1, .idx=1 },
	{ .name="dram",     .loop=src_dram_loop,    .cost_pct_x100= 14000,
	  .yield_bps=  28u*1024u*1024u,        .bytes_per_iter=  2, .enabled=1, .idx=2 },
	{ .name="irq-stat", .loop=src_irqstat_loop, .cost_pct_x100=   200,
	  .yield_bps=  50u*1024u,              .bytes_per_iter=500, .enabled=1, .idx=3 },
};
#define N_SOURCES (sizeof(g_sources) / sizeof(g_sources[0]))

static src_t *find_source(const char *name) {
	for (size_t i = 0; i < N_SOURCES; i++)
		if (strcmp(g_sources[i].name, name) == 0) return &g_sources[i];
	return NULL;
}

static uint32_t sources_active_mask(void) {
	uint32_t m = 0;
	for (size_t i = 0; i < N_SOURCES; i++)
		if (atomic_load(&g_sources[i].active)) m |= (1u << g_sources[i].idx);
	return m;
}
static uint32_t sources_healthy_mask(void) {
	uint32_t m = 0;
	for (size_t i = 0; i < N_SOURCES; i++)
		if (!atomic_load(&g_sources[i].health.failed)) m |= (1u << g_sources[i].idx);
	return m;
}

/* Single-writer per shard (no lock). Output is buffered locally and flushed
 * to the pool in batches — cuts pool-mutex acquisitions by ~16× vs pushing
 * every 16 bytes and was measured as the dominant win after sharding. */
static void absorb(src_t *s, __m128i sample) {
	uint8_t hb = (uint8_t)_mm_cvtsi128_si64(sample);
	if (health_feed(&s->health, hb) < 0) return;

	/* Debug: if raw-dump is enabled for this source, record the health byte
	 * (pre-extractor) for later NIST 800-90B min-entropy assessment. */
	if (s->raw_fd >= 0) (void)!write(s->raw_fd, &hb, 1);

	__m128i acc = _mm_loadu_si128((const __m128i *)&s->acc);
	acc = gf128_mul(_mm_xor_si128(acc, sample), g_H);
	_mm_storeu_si128((__m128i *)&s->acc, acc);

	if ((++s->absorb_count & (MIN_ENTROPY_RATIO - 1)) == 0) {
		_mm_storeu_si128((__m128i *)(s->emit_buf + s->emit_off), acc);
		s->emit_off += 16;
		if (s->emit_off >= SRC_EMIT_BATCH) {
			pool_push(s->emit_buf, s->emit_off);
			s->emit_off = 0;
		}
	}
}

/* ───────────────────────── Leases ───────────────────────── */

typedef struct lease {
	_Atomic uint32_t id;
	int              fd;
	trandom_req_t    req;
} lease_t;

static lease_t         g_leases[MAX_LEASES];
static pthread_mutex_t g_leases_mtx = PTHREAD_MUTEX_INITIALIZER;
static _Atomic uint32_t g_next_lease_id = 1;

static lease_t *lease_alloc(int fd, const trandom_req_t *req) {
	pthread_mutex_lock(&g_leases_mtx);
	for (size_t i = 0; i < MAX_LEASES; i++) {
		if (atomic_load(&g_leases[i].id) == 0) {
			g_leases[i].fd = fd;
			g_leases[i].req = *req;
			uint32_t id = atomic_fetch_add(&g_next_lease_id, 1);
			atomic_store(&g_leases[i].id, id);
			pthread_mutex_unlock(&g_leases_mtx);
			return &g_leases[i];
		}
	}
	pthread_mutex_unlock(&g_leases_mtx);
	return NULL;
}

static void lease_free(lease_t *l) {
	atomic_store(&l->id, 0);
	l->fd = -1;
}

static uint64_t total_demand_bps(void) {
	uint64_t s = 0;
	for (size_t i = 0; i < MAX_LEASES; i++)
		if (atomic_load(&g_leases[i].id)) s += g_leases[i].req.sustained;
	return s;
}

/* ───────────────────────── Live CPU accounting ───────────────────────── */

static _Atomic uint32_t g_cpu_pct_x100;   /* % of one vCPU, measured last tick */
static _Atomic int      g_over_budget_ticks;

static uint32_t measure_cpu_tick(struct rusage *prev, uint64_t *prev_wall_ns) {
	struct rusage cur; getrusage(RUSAGE_SELF, &cur);
	struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
	uint64_t wall_ns = ts_to_ns(now);

	uint64_t prev_us = (uint64_t)prev->ru_utime.tv_sec * 1000000ULL + (uint64_t)prev->ru_utime.tv_usec
	                 + (uint64_t)prev->ru_stime.tv_sec * 1000000ULL + (uint64_t)prev->ru_stime.tv_usec;
	uint64_t cur_us  = (uint64_t)cur.ru_utime.tv_sec * 1000000ULL + (uint64_t)cur.ru_utime.tv_usec
	                 + (uint64_t)cur.ru_stime.tv_sec * 1000000ULL + (uint64_t)cur.ru_stime.tv_usec;

	uint64_t dcpu_us = cur_us - prev_us;
	uint64_t dwall_ns = wall_ns - *prev_wall_ns;
	uint32_t pct_x100 = 0;
	if (dwall_ns > 0) {
		/* pct×100 of one vCPU = (dcpu_us / (dwall_ns/1000)) * 100 * 100
		 *                     = dcpu_us * 10^7 / dwall_ns */
		pct_x100 = (uint32_t)((dcpu_us * 10000000ULL) / dwall_ns);
	}
	*prev = cur;
	*prev_wall_ns = wall_ns;
	return pct_x100;
}

/* ───────────────────────── Scheduler ───────────────────────── */

static int cmp_src_cost(const void *a, const void *b) {
	const src_t *const *pa = a, *const *pb = b;
	return (int)(*pa)->cost_pct_x100 - (int)(*pb)->cost_pct_x100;
}

static void *scheduler_thread(void *_arg) {
	(void)_arg;
	pthread_setname_np(pthread_self(), "trand-sched");
	src_t *sorted[N_SOURCES];
	for (size_t i = 0; i < N_SOURCES; i++) sorted[i] = &g_sources[i];
	qsort(sorted, N_SOURCES, sizeof sorted[0], cmp_src_cost);

	struct rusage prev_ru;   getrusage(RUSAGE_SELF, &prev_ru);
	struct timespec now;     clock_gettime(CLOCK_MONOTONIC, &now);
	uint64_t prev_wall_ns = ts_to_ns(now);

	while (!atomic_load(&g_stop)) {
		uint32_t cpu_pct_x100 = measure_cpu_tick(&prev_ru, &prev_wall_ns);
		atomic_store(&g_cpu_pct_x100, cpu_pct_x100);

		uint64_t demand = total_demand_bps();
		uint64_t covered = 0;
		int over = cpu_pct_x100 > g_cpu_budget_x100 + g_cpu_budget_x100 / 5;  /* +20% hyst */
		int under = cpu_pct_x100 < g_cpu_budget_x100 * 4 / 5;                  /* −20% hyst */
		int over_ticks = atomic_load(&g_over_budget_ticks);
		if (over) over_ticks++;
		else if (under) over_ticks = 0;

		/* Decide activation target cost: halve budget for each sustained
		 * over-budget tick beyond the first. Cap the shift so we can always
		 * recover — the cheapest source is force-activated below anyway. */
		uint32_t budget_static = g_cpu_budget_x100;
		if (over_ticks > 1) {
			int shift = over_ticks - 1;
			if (shift > 10) shift = 10;          /* cap: /1024 floor */
			budget_static >>= shift;
		}

		uint32_t used_static = 0;
		for (size_t i = 0; i < N_SOURCES; i++) {
			src_t *s = sorted[i];
			if (!atomic_load(&s->enabled) || atomic_load(&s->health.failed)) {
				atomic_store(&s->active, 0);
				atomic_store(&s->target_bps, 0);
				continue;
			}
			int want = covered < demand && (used_static + s->cost_pct_x100) <= budget_static;
			/* keep cheapest healthy source always warm under demand */
			if (demand > 0 && !want && covered == 0) want = 1;
			atomic_store(&s->active, want);
			if (want) {
				covered += s->yield_bps;
				used_static += s->cost_pct_x100;
			}
		}
		atomic_store(&g_over_budget_ticks, over_ticks);

		/* Distribute demand across active sources as per-source target_bps.
		 * Cheapest first: each takes min(remaining_demand, its yield_bps).
		 * With no demand, set a small trickle (1 KB/s) on the cheapest source
		 * so the pool stays warm. */
		uint64_t remaining = demand;
		int      assigned_any = 0;
		for (size_t i = 0; i < N_SOURCES; i++) {
			src_t *s = sorted[i];
			if (!atomic_load(&s->active)) {
				atomic_store(&s->target_bps, 0);
				continue;
			}
			uint64_t share = remaining > s->yield_bps ? s->yield_bps : remaining;
			remaining -= share;
			if (share == 0 && !assigned_any) share = 1024;  /* keep pool warm */
			atomic_store(&s->target_bps, (uint32_t)share);
			if (share) assigned_any = 1;
		}

		struct timespec ts = {0, SCHED_PERIOD_MS * 1000 * 1000};
		nanosleep(&ts, NULL);
	}
	return NULL;
}

/* ───────────────────────── Socket server ───────────────────────── */

static void fill_stats(tr_reply_t *rep) {
	rep->pool_bytes      = pool_fill();
	rep->cpu_pct_x100    = atomic_load(&g_cpu_pct_x100);
	rep->sources_active  = sources_active_mask();
	rep->sources_healthy = sources_healthy_mask();
}

/* Reply header + payload in one writev — halves syscalls on the hot read path. */
static int write_reply_with_data(int fd, const tr_reply_t *rep,
                                  const void *data, size_t data_len) {
	struct iovec iov[2] = {
		{ .iov_base = (void *)rep,  .iov_len = sizeof *rep },
		{ .iov_base = (void *)data, .iov_len = data_len },
	};
	size_t total = sizeof *rep + data_len;
	ssize_t sent = 0;
	while ((size_t)sent < total) {
		ssize_t r = writev(fd, iov, data_len ? 2 : 1);
		if (r <= 0) return -1;
		sent += r;
		/* partial writev is rare on UNIX sockets within SO_SNDBUF; advance iov */
		if ((size_t)sent < total) {
			size_t consumed = (size_t)r;
			for (int i = 0; i < 2 && consumed; i++) {
				if (consumed >= iov[i].iov_len) {
					consumed -= iov[i].iov_len;
					iov[i].iov_len = 0;
				} else {
					iov[i].iov_base = (char *)iov[i].iov_base + consumed;
					iov[i].iov_len -= consumed;
					consumed = 0;
				}
			}
		}
	}
	return 0;
}

static void *client_thread(void *arg) {
	int fd = (int)(intptr_t)arg;
	pthread_setname_np(pthread_self(), "trand-client");
	lease_t *lease = NULL;
	uint8_t *data = malloc(MAX_READ_CHUNK);
	if (!data) { close(fd); return NULL; }

	for (;;) {
		tr_msg_t m;
		if (tr_io_read(fd, &m, sizeof m) < 0) break;
		tr_reply_t rep = {0};

		switch (m.op) {
		case TR_OP_LEASE_CREATE:
			if (lease) { rep.status = -EEXIST; break; }
			lease = lease_alloc(fd, &m.req);
			if (!lease) { rep.status = -ENOMEM; break; }
			rep.lease_id = atomic_load(&lease->id);
			break;

		case TR_OP_LEASE_UPDATE:
			if (!lease || atomic_load(&lease->id) != m.lease_id) { rep.status = -ENOENT; break; }
			lease->req = m.req;
			rep.lease_id = m.lease_id;
			break;

		case TR_OP_LEASE_RELEASE:
			if (lease) { lease_free(lease); lease = NULL; }
			fill_stats(&rep);
			tr_io_write(fd, &rep, sizeof rep);
			goto done;

		case TR_OP_STATS:
			if (lease) rep.lease_id = atomic_load(&lease->id);
			break;

		case TR_OP_READ: {
			if (!lease) { rep.status = -ENOENT; break; }
			if (sources_healthy_mask() == 0) { rep.status = -EIO; break; }
			size_t want = m.n;
			if (want == 0 || want > MAX_READ_CHUNK) want = MAX_READ_CHUNK;
			int blocking = !(lease->req.flags & TRANDOM_NONBLOCK);
			size_t got = pool_pull(data, want, blocking);
			if (got == 0 && !blocking) { rep.status = -EAGAIN; break; }
			rep.data_len = (uint32_t)got;
			fill_stats(&rep);
			if (write_reply_with_data(fd, &rep, data, got) < 0) goto done;
			continue;
		}

		default:
			rep.status = -EINVAL;
		}

		fill_stats(&rep);
		if (tr_io_write(fd, &rep, sizeof rep) < 0) break;
	}
done:
	if (lease) lease_free(lease);
	close(fd);
	free(data);
	return NULL;
}

static int listen_sock(const char *path) {
	/* Best-effort: create the parent dir (for non-systemd dev use). Systemd
	 * already pre-creates /run/trandom via RuntimeDirectory=trandom. */
	char parent[sizeof(((struct sockaddr_un *)0)->sun_path)];
	snprintf(parent, sizeof parent, "%s", path);
	char *slash = strrchr(parent, '/');
	if (slash && slash != parent) { *slash = '\0'; mkdir(parent, 0755); }

	unlink(path);
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0) return -1;
	struct sockaddr_un a = { .sun_family = AF_UNIX };
	strncpy(a.sun_path, path, sizeof a.sun_path - 1);
	if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) { close(s); return -1; }
	chmod(path, 0666);
	if (listen(s, 64) < 0) { close(s); return -1; }
	return s;
}

/* ───────────────────────── Init / main ───────────────────────── */

static void on_sig(int _s) { (void)_s; atomic_store(&g_stop, 1); }

static void seed_extractor(void) {
	uint8_t seed[16 + 16 * N_SOURCES];   /* 1 key + one shard per source */
	if (getrandom(seed, sizeof seed, 0) != (ssize_t)sizeof seed) {
		fprintf(stderr, "trandomd: getrandom failed\n"); exit(1);
	}
	g_H = _mm_loadu_si128((const __m128i *)seed);
	for (size_t i = 0; i < N_SOURCES; i++) {
		__m128i s0 = _mm_loadu_si128((const __m128i *)(seed + 16 + 16 * i));
		_mm_storeu_si128((__m128i *)&g_sources[i].acc, s0);
	}
}

static void usage(void) {
	fprintf(stderr,
		"trandomd [--sources=a,b,c] [--max-cpu=PCT] [--sock=PATH]\n"
		"  sources: tsc-phc,jitter,dram,irq-stat (default: all)\n"
		"  max-cpu: integer %% of one vCPU (default 10)\n");
	exit(2);
}

static void apply_sources_flag(const char *list) {
	for (size_t i = 0; i < N_SOURCES; i++) atomic_store(&g_sources[i].enabled, 0);
	char *s = strdup(list); char *p = s, *t;
	while ((t = strsep(&p, ",")) != NULL) {
		src_t *src = find_source(t);
		if (src) atomic_store(&src->enabled, 1);
		else fprintf(stderr, "trandomd: unknown source %s\n", t);
	}
	free(s);
}

int main(int argc, char **argv) {
	const char *sock_path = TRANDOM_SOCK;
	static const struct option opts[] = {
		{ "sources", required_argument, 0, 's' },
		{ "max-cpu", required_argument, 0, 'c' },
		{ "sock",    required_argument, 0, 'S' },
		{ 0, 0, 0, 0 }
	};
	int c;
	while ((c = getopt_long(argc, argv, "s:c:S:h", opts, NULL)) != -1) {
		switch (c) {
		case 's': apply_sources_flag(optarg); break;
		case 'c': g_cpu_budget_x100 = (uint32_t)(atoi(optarg) * 100); break;
		case 'S': sock_path = optarg; break;
		default:  usage();
		}
	}

	/* sigaction, not signal() — BSD signal() sets SA_RESTART implicitly,
	 * which would prevent accept() from returning EINTR on SIGTERM. */
	struct sigaction sa = { .sa_handler = on_sig };
	sigaction(SIGINT,  &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	struct sigaction sp = { .sa_handler = SIG_IGN };
	sigaction(SIGPIPE, &sp, NULL);

	seed_extractor();

	void *dram = mmap(NULL, DRAM_BUF_SZ, PROT_READ | PROT_WRITE,
	                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (dram != MAP_FAILED) {
		for (size_t i = 0; i < DRAM_BUF_SZ; i += 4096) ((uint8_t *)dram)[i] = (uint8_t)i;
		find_source("dram")->state = dram;
	}

	/* If TRANDOM_RAW_DUMP_DIR is set, open per-source raw-sample dump files.
	 * Each source writes one byte per absorb (the health-test byte, which is
	 * the low byte of the 128-bit sample). Enables independent NIST 800-90B
	 * min-entropy assessment of each physical source's pre-extractor signal. */
	const char *raw_dir = getenv("TRANDOM_RAW_DUMP_DIR");
	for (size_t i = 0; i < N_SOURCES; i++) g_sources[i].raw_fd = -1;
	if (raw_dir) {
		mkdir(raw_dir, 0755);
		for (size_t i = 0; i < N_SOURCES; i++) {
			char p[512];
			snprintf(p, sizeof p, "%s/%s.bin", raw_dir, g_sources[i].name);
			g_sources[i].raw_fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
			if (g_sources[i].raw_fd < 0) {
				fprintf(stderr, "trandomd: raw-dump open %s failed\n", p);
			} else {
				fprintf(stderr, "trandomd: raw-dumping %s → %s\n", g_sources[i].name, p);
			}
		}
	}

	for (size_t i = 0; i < N_SOURCES; i++)
		pthread_create(&g_sources[i].thr, NULL, src_thread, &g_sources[i]);

	pthread_t sched;
	pthread_create(&sched, NULL, scheduler_thread, NULL);

	int ls = listen_sock(sock_path);
	if (ls < 0) { perror("listen"); return 1; }

	while (!atomic_load(&g_stop)) {
		int c2 = accept(ls, NULL, NULL);
		if (c2 < 0) { if (errno == EINTR) continue; break; }
		pthread_t t;
		pthread_create(&t, NULL, client_thread, (void *)(intptr_t)c2);
		pthread_detach(t);
	}

	atomic_store(&g_stop, 1);
	pthread_cond_broadcast(&g_pool_cv);
	for (size_t i = 0; i < N_SOURCES; i++) {
		pthread_join(g_sources[i].thr, NULL);
		if (g_sources[i].raw_fd >= 0) close(g_sources[i].raw_fd);
	}
	pthread_join(sched, NULL);
	close(ls);
	unlink(sock_path);
	if (dram != MAP_FAILED) munmap(dram, DRAM_BUF_SZ);
	return 0;
}
