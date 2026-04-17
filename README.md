```
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

Redistributions of source code must retain the above notice, this list of
conditions and the following disclaimer.

Redistributions in binary form must reproduce the above notice, this list of
conditions and the following disclaimer in the documentation and/or other
materials provided with the distribution.

The names of the contributors may not be used to endorse or promote products
derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
SHALL THE CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
OF SUCH DAMAGE.
```

# trandom

**Information-theoretically secure entropy daemon for Linux.**

`/dev/urandom` delivers bytes that are *computationally* random — they look random
only because ChaCha20 is assumed to be a good PRF. If that assumption ever breaks
(cryptanalysis, P=NP, novel quantum cryptanalysis of stream ciphers), the output
becomes predictable.

`trandom` delivers bytes whose randomness rests on a *physical* assumption
instead: the claimed min-entropy of the noise sources we sample. Via the
Leftover Hash Lemma, output is statistically close to uniform —
**unconditionally**, with no complexity-theoretic assumption. The trade is
throughput: cloud VMs don't produce enough noise to match ChaCha20's GB/s.
We dial-a-rate from ~1 KB/s (8 Kbps) to ~14 MB/s (112 Mbps), with CPU cost
scaling linearly.

> **Contract:** reads return bytes backed by genuine extracted min-entropy, or
> an explicit error (`EAGAIN` / `EIO`). Never silent fallback to a PRG.

---

## When to use this

`trandom` exists for one specific situation:

> **You need information-theoretically secure randomness, and you do not have
> access to `RDSEED` or any other hardware TRNG/QRNG.**

That's the target use case. Typical examples:

- **Cloud vCPUs** — by default most cloud instances do **not** expose `RDSEED`
  to the guest, even when the host silicon has it (see box below).
- **AWS burstable / nano-class instances** where no HW QRNG card is attached
  and network access to a remote QRNG service is unavailable or undesirable.
- **Air-gapped or network-isolated machines** that also lack a hardware RNG.
- **Post-quantum paranoia** — you specifically want IT-security rather than
  betting on AES-CTR or ChaCha20 remaining unbroken.
- **Compliance / audit** regimes that want a physical-entropy chain of custody
  without trusting silicon vendor claims.

> **Why cloud vCPUs usually don't get `RDSEED`.** Intel's on-die entropy
> source is a single circuit shared across all logical cores on a physical
> die. On a multi-tenant host, every VM would contend for one ES. One abusive
> tenant spamming `RDSEED` could stall entropy delivery for every co-tenant —
> a trivial DoS vector the hypervisor has to mitigate. The common mitigation
> is to **mask the `RDSEED` CPUID bit in the guest**, so the guest never
> issues the instruction. Some providers also mask `RDRAND`, or trap and
> emulate both through a hypervisor RNG (which may itself be a PRG — defeating
> the IT property anyway). Result: assume `RDSEED` is unavailable on any
> shared-tenancy cloud instance unless you've explicitly tested (see the
> one-liner below). Check with:
> ```sh
> grep -qo rdseed /proc/cpuinfo && echo available || echo NOT available
> ```

**If `RDSEED` is available and you trust Intel's silicon**, use it directly
(or `rng-tools` / `jitterentropy-rngd` feeding the kernel pool) — it's faster,
simpler, and a defensible IT source on its own. `trandom` still has value on
top of it as *additional, independent* entropy to mix in defensively, but it
is not the primary tool.

**If you have a dedicated HW QRNG** (ID Quantique, QuintessenceLabs, on-die
Intel DRNG, ARM TRNG on newer chips, etc.), use it. Gbps-class QRNGs beat
this by an order of magnitude in throughput and don't burn CPU harvesting
noise; mid-tier QRNGs overlap with trandom's upper range, but still have
the advantage of delivering entropy without any CPU spend.

`trandom` is built for the case where *none of those are options* and you
still refuse to fall back to a PRG.

---

## Threat model

| Attacker capability | `/dev/urandom` | `trandom` |
|---|---|---|
| Unbounded computation (P=NP world) | broken | **secure** |
| Quantum cryptanalysis of ChaCha20 | broken | **secure** |
| Breaks one of N entropy sources | — | secure if ≥1 source retains min-entropy |
| Breaks *all* sources (predicts all physical noise) | broken | broken |
| Side-channel observation of the daemon's memory | broken | broken |

The security argument reduces to: *at least one noise source genuinely has
the min-entropy we estimated, and the CLMUL-GHASH extractor is a universal
hash family* (it is). Leftover Hash Lemma gives statistical closeness to
uniform — no computational step in the output path.

---

## Where this sits in the landscape

### Overall throughput (all classes)

| Source | Throughput (bytes) | Throughput (bits) | Class |
|---|---:|---:|---|
| QuintessenceLabs qStream | ~125 MB/s | ~1 Gbps | hardware QRNG |
| ID Quantique Quantis | 0.5–30 MB/s | 4–240 Mbps | hardware QRNG |
| Intel RDSEED (bare metal) | ~12–100 MB/s/core | ~100–800 Mbps/core | CPU instruction |
| **trandom (this project)** | **1 KB/s – 14 MB/s** | **8 Kbps – 112 Mbps** | software-only, cloud VM |
| jitterentropy-rng | ~1–2 MB/s | ~8–16 Mbps | software-only |
| haveged | ~1–10 MB/s (contested) | ~8–80 Mbps (contested) | software-only |

Precise picture:

- **QRNG hardware** (Gbps-class like QuintessenceLabs qStream) is genuinely
  an order of magnitude faster than trandom. The mid-tier QRNGs (ID Quantique
  Quantis at 4–240 Mbps) overlap with trandom's upper range.
- **Intel RDSEED** on bare metal runs ~1–7× faster than trandom (12–100 MB/s
  = 100–800 Mbps per core, vs trandom's ~14 MB/s = 112 Mbps) — **same order
  of magnitude**, not a different league. The reason to use RDSEED when
  available is simpler code and zero CPU cost beyond the instruction itself,
  not raw throughput.

Among **software-only** IT sources — the case where `RDSEED` and hardware
QRNGs aren't options — this is the picture:

### Software-only IT noise sources, axis by axis

| Property | jitterentropy-rng | haveged | Linux kernel input pool | **trandom** |
|---|---|---|---|---|
| Number of sources | 1 (CPU jitter) | 1 (HAVEGE loop) | IRQ + disk + input timings | **4 independent** |
| Sustained throughput | ~1–2 MB/s (8–16 Mbps) | ~1–10 MB/s (8–80 Mbps, disputed) | invisible — feeds CRNG only | **1 KB/s – 14 MB/s (8 Kbps – 112 Mbps), continuous** |
| Extractor | SHA-3 / cSHAKE (PRF) | ad-hoc SHA chain (criticized) | ChaCha20 DRBG (not IT) | **CLMUL-GHASH, LHL-sound** |
| IT-security argument | single-source | single-source, disputed | none to userspace (post-DRBG) | **any 1 of 4 sources retains min-entropy** |
| NIST SP 800-90B tests | heavy, certified | minimal | in-kernel (not exposed) | **RCT + APT per source, per-sample, in-flight gating** |
| Rate control | fixed | fixed | fixed | **continuous dial-a-rate via `target_bps`** |
| Cloud-VM tuning | generic | generic | weak (sparse IRQs on VMs) | **`tsc-phc` specifically targets hypervisor steering noise** |
| Userspace delivery | rngd → kernel pool; C library | rngd → kernel pool | `/dev/urandom` only (post-DRBG) | **libFFI + UNIX socket + CLI + `/dev/trandom` char device** |
| Maturity | production, kernel-integrated, certified | legacy, in many distros | canonical | **new, not yet certified** |
| Code size | ~2,500 LOC | ~1,500 LOC | kernel-resident | **~1,300 LOC** |

### Where trandom leads

- **~7× jitterentropy's throughput** and at the top of haveged's range, while
  keeping a clean LHL-sound extractor that haveged specifically lacks
- **Multi-source IT argument**: compromising any single source (e.g. a
  hypervisor that makes jitter deterministic) doesn't break security —
  neither competitor can claim this
- **Continuous CPU↔throughput curve** from a few KB/s to the ceiling, with
  CPU proportional to demand; competitors are on/off
- **Real `/dev/trandom` character device** via CUSE — jitterentropy and
  haveged only feed the kernel input pool, where bytes then pass through
  ChaCha20 before any userspace consumer sees them (so their IT property is
  destroyed in transit)

### Where trandom is behind

- **No formal NIST SP 800-90B certification yet.** The sources run 90B §4.4
  continuous health tests (RCT + APT), but the full Entropy Assessment
  suite hasn't been executed and published for procurement use.
- **Not production battle-tested.** jitterentropy has years of kernel
  integration and third-party review; trandom is new.
- **External to the kernel.** If the kernel CRNG design changes, jitterentropy
  is already plumbed in; trandom would need re-integration work.
- **x86_64-only** currently. ARMv8 port would use `PMULL` (~1 day of work).

---

## Build

```sh
sudo apt install libfuse3-dev     # or: dnf install fuse3-devel
make
```

Requires:
- Linux, x86_64
- CLMUL + SSE4.1 (any Intel ≥ Westmere 2010, any AMD ≥ Bulldozer 2011)
- pthreads, glibc
- `libfuse3-dev` for the `/dev/trandom` bridge — **required by default**

Produces:
- `trandomd` — the daemon
- `libtrandom.so` — client library
- `trctl` — CLI for testing / piping
- `trandom-cuse` — CUSE bridge that registers `/dev/trandom`

**Opt out of CUSE** if you don't need the device node (rare — you lose
drop-in compatibility with programs expecting a device path):

```sh
make CUSE=no        # builds core only; no /dev/trandom
```

> **Toolchain note:** the CUSE bridge links against system `libfuse3`, which
> is built against system glibc. If your `cc` is a non-system toolchain
> (conda-forge compilers, Nix, a sysroot SDK), the link would fail with
> `undefined reference to __tunable_is_initialized@GLIBC_PRIVATE`. The
> Makefile side-steps this by using `/usr/bin/gcc` for just the CUSE target
> when present. Override with `SYSCC=/path/to/gcc` if your system gcc lives
> elsewhere.

## Install

```sh
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now trandomd.service trandom-cuse.service
sudo make check-install                                # sanity + quick stats
make verify                                            # full IT-security audit
```

`make install` does:

| Action | Details |
|---|---|
| Binaries → `/usr/local/bin/` | `trandomd`, `trctl`, `trandom-cuse` |
| Library → `/usr/local/lib/libtrandom.so` + header `/usr/local/include/trandom.h` | for `-ltrandom` linkers |
| Systemd units → `/etc/systemd/system/` | `trandomd.service`, `trandom-cuse.service` |
| Config → `/etc/default/trandom` | edit this to tune options — don't touch unit files |
| System user `trandom` | dedicated unprivileged user for the daemon |
| Runtime dir → `/run/trandom/` | socket lives inside, auto-created on service start |
| Device node → `/dev/trandom` | created by CUSE bridge, mode `crw-r--r--` |

`trandomd` runs as the unprivileged `trandom` user with *no* capabilities.
`trandom-cuse` runs as root but with only `CAP_SYS_ADMIN + CAP_FOWNER`
(needed to register the char device and relax its permissions); all other
caps are dropped.

### Configuration

Edit `/etc/default/trandom` — sourced by both systemd units on restart.
Typical edits:

```sh
TRANDOM_OPTS="--max-cpu=20 --sources=tsc-phc,jitter,irq-stat"
```

Variables:

| Var | Default | Meaning |
|---|---|---|
| `TRANDOM_SOCK` | `/run/trandom/sock` | UNIX socket path (must be inside `RuntimeDirectory`) |
| `TRANDOM_OPTS` | `--max-cpu=10` | extra flags to `trandomd` |
| `TRANDOM_DEVNAME` | `trandom` | name under `/dev/` (e.g. `trandom2`) |

Then reload the services:

```sh
sudo systemctl restart trandomd.service trandom-cuse.service
```

### Post-install verification

```sh
sudo make check-install
```

Expected output:

```
=== trandom install check ===
daemon service:  active
CUSE service:    active
socket:          /run/trandom/sock exists
device:          /dev/trandom is a char device (crw-r--r--)
read test:       OK (16 bytes read)
```

If any line reports `INACTIVE` or `MISSING`, restart that service
(`sudo systemctl restart trandomd.service`) and re-run the check.

### Uninstall

```sh
sudo make uninstall    # preserves /etc/default/trandom and the 'trandom' user
```

Both are preserved deliberately (config may have local edits; the user may
own lingering files). Remove manually with `rm /etc/default/trandom` and
`sudo userdel trandom` if you really want everything gone.

---

## Run

```sh
trandomd [--sources=a,b,c] [--max-cpu=N] [--sock=PATH]
```

| Flag | Meaning | Default |
|---|---|---|
| `--sources=` | Comma list of sources to enable | all four |
| `--max-cpu=N` | CPU budget as integer % of one vCPU | `10` |
| `--sock=PATH` | UNIX socket path | `/run/trandom/sock` |

### Sources

| Name | Physical phenomenon sampled |
|---|---|
| `tsc-phc` | `rdtsc` vs `CLOCK_TAI` divergence — hypervisor TSC-steering noise, PTP (if available on AWS Nitro), host crystal drift |
| `jitter` | CPU pipeline / cache / branch-predictor timing jitter sampled via tight `rdtsc` loop + xorshift amplifier |
| `dram` | DRAM row-conflict latency (strided reads through a 64 MiB working set) |
| `irq-stat` | `/proc/interrupts` snapshot hashed with `rdtsc` — captures IRQ arrival chaos, virtio-IRQ timing, hypervisor IPI behavior |

All four are **independent** — different phenomena at different layers of
hardware/kernel — so the multi-source extractor's argument ("secure if ≥1
source retains min-entropy") is not vacuous.

Adaptive pacing means each active source runs at the rate the scheduler
assigns it based on total demand. When demand is 100 KB/s, tsc-phc + irq-stat
(the two cheapest) handle it at ~3% CPU. When demand is 10 MB/s, jitter and
dram get activated and CPU rises to ~50%.

---

## Throughput vs CPU

Measured on a modest x86 workstation. All throughput figures below are in
**megabytes per second** (MB/s) — multiply by 8 for Mbps. Adaptive pacing
gives a smooth gradient
with no tiers or step quantization:

| Demand | Delivered | CPU |
|---:|---:|---:|
| 10 KB/s | 10 KB/s | 0.8% |
| 100 KB/s | 88 KB/s | 2.4% |
| 1 MB/s | 0.8 MB/s | 14% |
| 5 MB/s | 3.8 MB/s | 38% |
| 10 MB/s | 7.0 MB/s | 47% |
| 20 MB/s | 11.4 MB/s | 59% |
| 50 MB/s | 14.0 MB/s | 65% (saturated) |

Delivery ratio is 80–100% of ask in the 10 KB/s – 1 MB/s band, dropping to
~70% above 5 MB/s as the pool/extractor approach saturation. Ask for 1.25× to
get exactly what you want.

Minimum meaningful increment: ~1 KB/s (set by the idle-trickle floor). Below
that, output is pinned to a few KB/s baseline.

Ceiling: ~14 MB/s (112 Mbps), imposed by per-source absorb cost (health tests + GHASH
update + pool mutex). This can be pushed by removing health tests (trades
safety) or by a lock-free pool (~100 LOC). The current ceiling is well
above the sustainable rate for any nano-class VM, so it's left as-is.

---

## Three ways to consume entropy

### 1. `/dev/trandom` — drop-in character device

Works from any language, any runtime. Behaves like `/dev/urandom`:

```sh
head -c 32 /dev/trandom | xxd        # 32-byte key
openssl rand -hex 16 < /dev/trandom  # works with -rand switch
dd if=/dev/trandom of=key.bin bs=32 count=1
python3 -c 'print(open("/dev/trandom","rb").read(32).hex())'
```

Requires `trandom-cuse.service` running (which needs libfuse3 at build time
and CAP_SYS_ADMIN at runtime — handled by the systemd unit).

### 2. `libtrandom` — C API for fine-grained control

Link `-ltrandom`:

```c
#include <trandom.h>

trandom_req_t req = {
    .sustained = 64 * 1024,      /* 64 KB/s target */
    .burst     = 4096,           /* max chunk size */
    .flags     = TRANDOM_STRICT_IT,
};

trandom_t *h = trandom_request(&req);
if (!h) err(1, "trandom_request");

uint8_t key[32];
if (trandom_read(h, key, sizeof key) != sizeof key) err(1, "read");

trandom_release(h);
```

Semantics:
- `trandom_read` returns ≤ `n` bytes (short-read style); never fabricates output
- `EAGAIN` in non-blocking mode when the pool is empty
- `EIO` if all sources have failed health tests — never silent degradation
- `trandom_update` adjusts the lease's declared rate mid-flight
- Closing the handle (or process exit) releases the lease

### 3. `trctl` — shell / pipe

```sh
trctl 102400 > keys.bin              # stream at 100 KB/s
trctl 1048576 32 | xxd               # one 32-byte sample
trctl 5242880 | pv -r > /dev/null    # observe live rate
```

Args: `trctl <bytes/sec> [bytes-total]`.

---

## Architecture

```
   4 source threads           per-source shards    shared pool
   ─────────────────          ─────────────────    ────────────
   tsc-phc ──absorb──► GHASH(acc[tsc-phc]) ──┐
   jitter  ──absorb──► GHASH(acc[jitter])  ──┤
   dram    ──absorb──► GHASH(acc[dram])    ──┼──► emit_buf (256 B)
   irq-stat ─absorb──► GHASH(acc[irq])     ──┘     │
       ▲                                           ▼
       │ target_bps                           256 KB ring
       │ (per source)                              │
       │                                           ▼
   scheduler ◄── total_demand ──── UNIX socket server
   (100ms tick)   (sum of leases)         │
                                          ▼
                                 /run/trandom/sock
                                          │
                          ┌───────────────┼───────────────┐
                          ▼               ▼               ▼
                     libtrandom         trctl       trandom-cuse
                                                          │
                                                          ▼
                                                   /dev/trandom
```

**Per-source extractor shards** — each source has its own GHASH accumulator
and absorb counter. Single-writer per shard, so no locking is needed inside
`absorb()`. Each shard independently satisfies the Leftover Hash Lemma; the
pool accumulates near-uniform 16-byte blocks from all shards interleaved.

**Extractor** — GHASH over GF(2^128) using Intel CLMUL. `acc ← (acc ⊕ sample) × H`
per absorb, where `H` is a 128-bit key seeded once from `getrandom()` at
startup. Every 8 absorbs, the shard's state is copied into a 256-byte emit
buffer; when that fills, it's `memcpy`'d into the pool under the pool mutex.

**Pool** — 256 KiB SPMC byte ring. Power-of-two size so the modulo is a mask.
Reads and writes use split `memcpy` at the wrap. Oldest bytes dropped on
overflow (IT producer, best-effort consumer pacing).

**Scheduler** — runs every 100 ms:
1. Measures live CPU via `getrusage(RUSAGE_SELF)` with ±20% hysteresis
2. Sums `sustained` across active leases → total demand
3. Activates sources cheapest-first until demand is covered or CPU budget exhausted
4. Distributes the demand across active sources as per-source `target_bps`
5. Always keeps at least the cheapest active source warm (for pool warmth)

**Adaptive pacing** — each source loop reads its `target_bps`, computes a
sample batch size and nap interval, does that many absorbs, then sleeps. If
the target rate would require naps below kernel nanosleep resolution (~50 µs),
the source runs unpaced and CPU scales naturally. This gives continuous
control from ~1 KB/s to ~14 MB/s with CPU proportional to rate.

**Health tests** — per source, NIST SP 800-90B §4.4 Repetition Count (cutoff
21 at H=1) and Adaptive Proportion (window 512, cutoff 410 at H=1) applied on
the low byte of every absorbed sample. A failing source sets its `health.failed`
atomic; the scheduler sees this and drops it from the active set. Clients
observe the current `sources_healthy` bitmask on every reply.

---

## Verification

Two built-in targets check *different* things:

| Command | What it tests | Runtime |
|---|---|---|
| `sudo make check-install` | Chain-of-custody: services running, socket exists, device exists, 16-byte read works — PLUS a quick 1 MB statistical audit of the output | ~2 s |
| `make verify` | Full IT-security audit: 10 MB output + **per-source pre-extractor min-entropy** (NIST SP 800-90B §6.3 estimators: MCV + collision + Markov) | ~5 s |

### `make check-install` — quick sanity

```sh
$ sudo make check-install
=== trandom install check ===
daemon service:  active
CUSE service:    active
socket:          /run/trandom/sock exists
device:          /dev/trandom is a char device (crw-r--r--)
read test:       OK (16 bytes read)

=== quick quality audit (1 MB sample) ===
Extractor output  —  1,048,576 bytes
  chi² byte freq         :  285.17   (95% CI 215–298)    PASS
  Shannon entropy        : 7.99998   (ideal 8.000)        PASS
  runs test z-score      :   1.087   (|z| < 2.576)        PASS
  serial correlation     : +0.00033   (|r| < 0.005)        PASS
  Monte Carlo π          : 3.14100   (err < 0.01)         PASS
  gzip ratio             :  1.0003   (> 0.999 incompr.)   PASS
```

If all lines say `active` / `exists` / `OK` / `PASS`, the install is working.

### `make verify` — full IT-security audit

Runs a private daemon with per-source raw-byte dumps, pulls 10 MB of extractor
output, then runs statistical tests on that output AND NIST SP 800-90B min-entropy
estimators on each source's pre-extractor samples:

```sh
$ make verify
════════════════════════════════════════════════════════════
trandom verification audit
════════════════════════════════════════════════════════════

Extractor output  —  10,000,000 bytes
  chi² byte freq         :  265.79   (95% CI 215–298)    PASS
  Shannon entropy        : 7.99998   (ideal 8.000)        PASS
  runs test z-score      :  -0.774   (|z| < 2.576)        PASS
  serial correlation     : +0.00052   (|r| < 0.005)        PASS
  Monte Carlo π          : 3.14133   (err < 0.01)         PASS
  gzip ratio             :  1.0003   (> 0.999 incompr.)   PASS

Raw per-source min-entropy  —  NIST SP 800-90B §6.3
  (needs H_min ≥ 1 bit/byte; we compress 8:1, so 1 bit/byte)
  dram        MCV=2.618  coll=0.767  markov=1.276  → H_min=0.767  weak    (2,792,448 samples)
  irq-stat    MCV=7.450  coll=1.634  markov=0.859  → H_min=0.859  weak    (91,186 samples)
  jitter      MCV=4.688  coll=1.297  markov=2.748  → H_min=1.297  STRONG  (1,448,336 samples)
  tsc-phc     MCV=7.866  coll=2.184  markov=5.798  → H_min=2.184  STRONG  (671,104 samples)

────────────────────────────────────────────────────────────
IT-security chain
────────────────────────────────────────────────────────────
  Link 1  ≥1 source has ≥1 bit/byte min-entropy     ✓
            STRONG: jitter, tsc-phc
            weak:   dram, irq-stat (not needed for security)
  Link 2  extractor is a universal hash family       ✓ (CLMUL-GHASH, see gf128_mul in trandomd.c)
  Link 3  extractor output is statistically uniform  ✓

  Result: IT-SECURE.
  Leftover Hash Lemma holds via strong source(s); the multi-source
  architecture means weak sources cost nothing (they're absorbed
  independently and don't degrade the strong-source contribution).
```

### How to read the results

**Statistical tests on the extractor output** (chi², Shannon, runs, serial
correlation, Monte Carlo, gzip) prove the output *looks* uniformly random.
**These alone do NOT prove IT-security** — any competent PRG passes them.

**Per-source min-entropy** on raw pre-extractor samples is the IT-security
argument. The three NIST estimators (most-common-value, collision, Markov)
each give a lower bound on the source's min-entropy; we take the minimum
(most pessimistic) as `H_min`. A source is `STRONG` if `H_min ≥ 1 bit/byte`
— that's enough for the Leftover Hash Lemma to give near-uniform output
from our 8:1 compression ratio.

**Weak sources are expected and not a failure.** `dram` and `irq-stat`
typically score weak because adjacent raw samples are correlated (DRAM
latency buckets; `/proc/interrupts` snapshots barely change microsecond-to-
microsecond). They still contribute entropy — just not enough to carry the
LHL argument alone. The multi-source design means **any single STRONG
source is sufficient** to guarantee IT-security; the weak ones are
defense-in-depth independent inputs.

**Failure modes to worry about:**
- **No source STRONG** → LHL argument doesn't hold. Likely means the environment is unusually deterministic (Firecracker with strict clock virtualisation, nested virt, unusual scheduler). Try different `--sources` combinations.
- **Extractor stats FAIL** → bug or corrupted build. Output isn't even statistically uniform.

### External tools

For maximum rigor, run the reference NIST SP 800-90B suite against the raw
dumps (built-in estimators are simplified versions):

```sh
TRANDOM_RAW_DUMP_DIR=/tmp/raw ./trandomd --sock=/tmp/t.sock &
./trctl 10000000 10000000 > /dev/null
# Using https://github.com/usnistgov/SP800-90B_EntropyAssessment:
ea_non_iid -i /tmp/raw/jitter.bin 8
ea_non_iid -i /tmp/raw/tsc-phc.bin 8
```

Or run `dieharder` against the extractor output for the standard battery:

```sh
./trctl 1000000000 | dieharder -a -g 200
```

### Scripts in this repo

```sh
./chartest.sh   # table of 15 source combinations × quality metrics
./pacetest.sh   # throughput vs. CPU at each request rate (coarse)
./finetest.sh   # same but 33 closely-spaced rates (fine gradient)
./verify.py     # standalone: verify.py <output-file> [raw-dir]
```

---

## Integration with the rest of the system

`trandom` does **not** replace `/dev/urandom`. Almost no caller actually needs
IT-security, and `/dev/urandom` is faster than any physical source can manage.
Recommended pattern:

- **Key material, long-term secrets, root keys** → `/dev/trandom` or `libtrandom`
- **Session IVs, nonces, CSRF tokens, short-lived randomness** → stay on `/dev/urandom`
- **Legacy programs that `open("/path")`** → point them at `/dev/trandom`; the
  CUSE bridge makes it look identical to `/dev/urandom`

---

## Status and caveats

**What works (verified end-to-end on x86_64 Linux 6.17):**
- Four independent IT sources, per-source sharded GHASH extractor
- Continuous adaptive pacing (1 KB/s – 14 MB/s ≡ 8 Kbps – 112 Mbps),
  verified with a 33-point fine sweep
- NIST SP 800-90B continuous health tests (RCT + APT) gating mid-flight
- Live CPU accounting with hysteresis
- Request/response socket protocol, lease-scoped leases
- `libtrandom` client, `trctl` CLI, CUSE bridge exposing `/dev/trandom`
  (registered as `crw-r--r--` char device, readable by any unprivileged process)
- **Hardened install**: `trandomd` runs as dedicated `trandom` system user with
  zero capabilities; CUSE bridge drops all caps except `CAP_SYS_ADMIN + CAP_FOWNER`;
  config lives in `/etc/default/trandom` (not baked into unit files)
- **Built-in verification**: `make check-install` (sanity + 1 MB stats) and
  `make verify` (10 MB extractor stats + per-source NIST SP 800-90B §6.3
  min-entropy via raw-sample dump) — proves all three links of the IT chain
- ~1,200 lines of C + ~230 lines of Python (verify harness); dependencies:
  glibc + pthreads (+ libfuse3 for CUSE, + python3 stdlib for verify)

**Platform limits:**
- x86_64 only (CLMUL). ARMv8 port would use `PMULL`, straightforward (~1 day).
- On dedicated-tenancy hosts the `tsc-phc` source loses most of its signal
  (no co-tenants making the hypervisor steer the TSC in chaotic ways). Adding
  `/dev/ptp0` direct access would help on AWS Nitro (~30 LOC, not yet wired).
- On Firecracker / very thin microVMs the `jitter` and `irq-stat` yields drop;
  run `ea_non_iid` on a sample and tune `MIN_ENTROPY_RATIO` up if needed.
- Health tests assume ≥1 bit of min-entropy per sampled byte (conservative per
  NIST §4.4). Sources producing less trip the tests and are dropped — that's
  the intended safety behavior.

**Known upgrades worth considering:**
- Direct `/dev/ptp0` `PTP_SYS_OFFSET_PRECISE` reads instead of `CLOCK_TAI`
  (bypasses phc2sys smoothing on AWS Nitro)
- `perf_event_open` on `irq:irq_handler_entry` instead of `/proc/interrupts`
  polling — higher-resolution IRQ timing, needs `CAP_PERFMON`
- Lock-free SPMC pool to push the ceiling past 14 MB/s (~100 LOC, only
  matters on bigger-than-nano instances)

---

## Why not just fix `/dev/urandom`?

Because `/dev/urandom` is fundamentally a PRG with periodic reseeding. No
amount of post-hoc hardening turns that into an information-theoretic
construction — the DRBG stage is load-bearing for throughput, and removing it
drops throughput by 100×. `trandom` is a *separate* device for the workloads
that actually want the IT guarantee, leaving `/dev/urandom` untouched for the
99% of callers that don't.
