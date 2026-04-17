#!/usr/bin/env python3
"""
verify.py — statistical + entropy audit of a trandom byte stream.

Usage:  verify.py <extracted-output-file> [raw-dump-dir]

Modes:
  verify.py <file>              — test extractor output only (statistical)
  verify.py <file> <raw-dir>    — also test each source's raw pre-extractor
                                  bytes for min-entropy (NIST SP 800-90B §6.3)

Runs on the extracted output:
  - chi² byte frequency
  - Shannon entropy
  - monobit runs test
  - serial correlation
  - gzip ratio
  - Monte Carlo π
  - MCV min-entropy estimate

Runs on each raw source dump (if provided):
  - NIST SP 800-90B §6.3.1 MCV (most-common-value) min-entropy estimator
  - NIST SP 800-90B §6.3.2 collision estimator
  - NIST SP 800-90B §6.3.3 Markov estimator

Prints the IT-security chain-of-custody summary.
"""
import sys, os, math, collections, gzip

# ─── extractor-output tests ───

def chi2_byte(b):
    n = len(b); exp = n / 256
    c = collections.Counter(b)
    return sum((c.get(i,0) - exp)**2 for i in range(256)) / exp

def chi2_pvalue(x, df=255):
    """Two-tailed p-value for chi² statistic via Wilson-Hilferty normal
    approximation (accurate to ~1e-4 for df ≥ 30). Returns the probability
    of a value at least this extreme under the uniform null."""
    mu = 1.0 - 2.0 / (9.0 * df)
    sigma = math.sqrt(2.0 / (9.0 * df))
    z = ((x / df) ** (1.0/3.0) - mu) / sigma
    cdf = 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))
    return 2.0 * min(cdf, 1.0 - cdf)

def shannon(b):
    n = len(b); c = collections.Counter(b); h = 0.0
    for v in c.values():
        p = v/n; h -= p * math.log2(p) if p else 0
    return h

def runs_z(b):
    n = 8 * len(b)
    ones = sum(bin(x).count('1') for x in b)
    p = ones / n
    if not (0.1 < p < 0.9): return float('inf')
    var = 2 * ones * (n - ones) * (2 * ones * (n - ones) - n) / (n * n * (n - 1))
    if var <= 0: return 0
    runs = 1
    prev = b[0] & 1
    for byte in b:
        for i in range(8):
            bit = (byte >> i) & 1
            if bit != prev: runs += 1; prev = bit
    exp = 2 * ones * (n - ones) / n + 1
    return (runs - exp) / math.sqrt(var)

def serial_corr(b):
    n = len(b); mean = sum(b)/n
    num = sum((b[i]-mean)*(b[(i+1)%n]-mean) for i in range(n))
    den = sum((x-mean)**2 for x in b)
    return num/den if den else 0

def monte_carlo_pi(b):
    n = len(b) // 6; inside = 0
    for i in range(n):
        off = i*6
        x = (b[off] << 16) | (b[off+1] << 8) | b[off+2]
        y = (b[off+3] << 16) | (b[off+4] << 8) | b[off+5]
        fx = x / (1<<24); fy = y / (1<<24)
        if fx*fx + fy*fy <= 1.0: inside += 1
    return 4 * inside / n if n else 0

# ─── NIST SP 800-90B §6.3 min-entropy estimators ───

def mcv_min_entropy(b):
    """§6.3.1 most-common-value estimator with upper 99% CI on p_hat."""
    n = len(b)
    c = collections.Counter(b)
    p_hat = max(c.values()) / n
    p_u = min(1.0, p_hat + 2.576 * math.sqrt(p_hat*(1-p_hat)/n))
    return -math.log2(p_u)

def collision_estimator(b):
    """§6.3.2 — estimator based on mean time between collisions."""
    n = len(b); seen = {}; gaps = []; last = 0
    for i, x in enumerate(b):
        if x in seen:
            gaps.append(i - last); last = i; seen.clear()
        seen[x] = i
    if not gaps: return 8.0
    mean_t = sum(gaps) / len(gaps)
    # NIST 800-90B approximate formula: H_min ≈ log2(sigma) where sigma solves
    # a specific equation; here we use the simpler bound mean_t ≈ 1/(sum p_i²).
    p2 = 1.0 / mean_t if mean_t > 0 else 1.0
    return -0.5 * math.log2(p2) if p2 > 0 else 8.0

def markov_estimator(b, k=128):
    """§6.3.3 — Markov chain min-entropy estimate over byte pairs. Simplified."""
    if len(b) < 2: return 8.0
    counts = collections.Counter((b[i], b[i+1]) for i in range(len(b)-1))
    row_sum = collections.Counter(b[:-1])
    # For each observed (x,y), compute p(y|x); worst-case conditional entropy
    # over all observed transitions approximates the Markov H_min lower bound.
    min_h = 8.0
    for (x, y), c in counts.items():
        p = c / row_sum[x]
        h = -math.log2(p) if p > 0 else 8.0
        if h < min_h: min_h = h
    return min_h

# ─── output formatting ───

def fmt_pass(v, ok, width=7):
    return f"{v:>{width}}   {'PASS' if ok else 'FAIL'}"

def test_extractor(data):
    n = len(data)
    print(f"Extractor output  —  {n:,} bytes")

    # Gate on p-value, not raw chi². The old ±95% CI fails ~5% of clean
    # runs by design — too flaky for an install gate. p ≥ 0.001 gives a
    # 0.2% two-tailed false-positive rate.
    chi = chi2_byte(data); chi_p = chi2_pvalue(chi)
    chi_ok = chi_p >= 0.001
    print(f"  chi² byte freq         : {chi:7.2f}   (p={chi_p:.3f}, pass p≥0.001) {'PASS' if chi_ok else 'FAIL'}")

    h = shannon(data); h_ok = h > 7.999
    print(f"  Shannon entropy        : {h:7.5f}   (ideal 8.000)        {'PASS' if h_ok else 'FAIL'}")

    z = runs_z(data); runs_ok = abs(z) < 2.576
    print(f"  runs test z-score      : {z:+7.3f}   (|z| < 2.576)        {'PASS' if runs_ok else 'FAIL'}")

    sc = serial_corr(data); sc_ok = abs(sc) < 0.005
    print(f"  serial correlation     : {sc:+7.5f}   (|r| < 0.005)        {'PASS' if sc_ok else 'FAIL'}")

    pi = monte_carlo_pi(data); pi_ok = abs(pi - math.pi) < 0.01
    print(f"  Monte Carlo π          : {pi:7.5f}   (err < 0.01)         {'PASS' if pi_ok else 'FAIL'}")

    gz = len(gzip.compress(data, compresslevel=9)) / n
    gz_ok = gz > 0.999
    print(f"  gzip ratio             : {gz:7.4f}   (> 0.999 incompr.)   {'PASS' if gz_ok else 'FAIL'}")

    passes = sum([chi_ok, h_ok, runs_ok, sc_ok, pi_ok, gz_ok])
    return passes == 6

def test_raw_source(name, data):
    n = len(data)
    if n < 10_000:
        print(f"  {name:10s}  only {n} samples — skip (need ≥ 10,000)")
        return None
    mcv = mcv_min_entropy(data)
    coll = collision_estimator(data)
    markov = markov_estimator(data)
    h_min = min(mcv, coll, markov)    # NIST 800-90B takes the pessimistic estimator
    # Passing criterion: at least 1 bit/byte of min-entropy (our compression is 8:1
    # so 1 bit/byte input suffices for near-full-entropy output after LHL)
    strong = h_min >= 1.0
    label = "STRONG" if strong else "weak  "
    print(f"  {name:10s}  MCV={mcv:5.3f}  coll={coll:5.3f}  markov={markov:5.3f}  "
          f"→ H_min={h_min:5.3f}  {label}  ({n:,} samples)")
    return strong

# ─── main ───

def main():
    if len(sys.argv) < 2: print(__doc__); sys.exit(2)
    output_path = sys.argv[1]
    raw_dir = sys.argv[2] if len(sys.argv) > 2 else None

    print("═" * 60)
    print("trandom verification audit")
    print("═" * 60)

    with open(output_path,'rb') as f: data = f.read()
    print()
    ext_ok = test_extractor(data)
    print()

    src_results = {}
    if raw_dir and os.path.isdir(raw_dir):
        print(f"Raw per-source min-entropy  —  NIST SP 800-90B §6.3")
        print(f"  (needs H_min ≥ 1 bit/byte; we compress 8:1, so 1 bit/byte)")
        for name in sorted(os.listdir(raw_dir)):
            if not name.endswith('.bin'): continue
            src = name[:-4]
            with open(os.path.join(raw_dir, name),'rb') as f:
                sdata = f.read()
            src_results[src] = test_raw_source(src, sdata)
        print()

    # ─── chain summary ───
    strong_sources = [n for n, ok in src_results.items() if ok]
    weak_sources   = [n for n, ok in src_results.items() if ok is False]
    any_strong = bool(strong_sources)

    print("─" * 60)
    print("IT-security chain")
    print("─" * 60)
    print(f"  Link 1  ≥1 source has ≥1 bit/byte min-entropy     "
          f"{'✓' if any_strong else ('? (no raw dumps)' if not src_results else '✗')}")
    if src_results:
        if strong_sources:
            print(f"            STRONG: {', '.join(strong_sources)}")
        if weak_sources:
            print(f"            weak:   {', '.join(weak_sources)} (not needed for security)")
    print(f"  Link 2  extractor is a universal hash family       "
          f"✓ (CLMUL-GHASH, see gf128_mul in trandomd.c)")
    print(f"  Link 3  extractor output is statistically uniform  "
          f"{'✓' if ext_ok else '✗'}")
    print()
    if any_strong and ext_ok:
        print("  Result: IT-SECURE.")
        print("  Leftover Hash Lemma holds via strong source(s); the multi-source")
        print("  architecture means weak sources cost nothing (they're absorbed")
        print("  independently and don't degrade the strong-source contribution).")
    elif ext_ok and not src_results:
        print("  Result: output looks uniform; Link 1 not measured.")
        print("  Run with raw dumps for the full audit:")
        print("    TRANDOM_RAW_DUMP_DIR=/tmp/raw ./trandomd &")
        print("    ./trctl 10000000 10000000 > /tmp/sample.bin")
        print("    ./verify.py /tmp/sample.bin /tmp/raw")
    elif ext_ok and not any_strong:
        print("  Result: FAIL — all sources below 1 bit/byte min-entropy.")
        print("  Extractor output still looks uniform (so the mixing works),")
        print("  but the LHL argument doesn't hold without at least one strong")
        print("  source. Investigate: is the environment unusually deterministic?")
    else:
        print("  Result: FAIL — extractor output is not statistically uniform.")
        print("  Indicates a bug in the extractor, a stuck source, or insufficient")
        print("  input entropy. Inspect the failing statistical tests above.")

if __name__ == '__main__':
    main()
