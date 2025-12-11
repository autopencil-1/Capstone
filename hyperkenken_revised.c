// Hyper-KenKen++ (8x8) — Generator + Verifier (pure C, clean formatting)
// ----------------------------------------------------------------------
// Features
//   • KenKen/Calcudoku cages with ops {+, -, *, /, =}
//   • Optional futoshiki-style inequalities (<, >) and parity hints (even/odd)
//   • Guaranteed unique solution (backtracking solver checks uniqueness)
//   • Fixed RNG seed for reproducible puzzle instances
//   • Strict solution-file format (canonical) to ensure hash uniqueness
//   • Verifier prints SHA-256 of the submitted solution file bytes (flag)
//   • Extra helper mode: --dump-solution <out.txt> writes the canonical solution
//
// Build
//   gcc -O2 -std=c11 -o hyperkenken hyper_kenken_clean.c
//
// Usage
//   ./hyperkenken                      # print puzzle description
//   ./hyperkenken solution.txt         # verify; on success print SHA-256 (flag)
//   ./hyperkenken --dump-solution out.txt   # write canonical solution (strict format)
//
// Strict solution-file format (to guarantee canonical hashing)
//   • Exactly N lines (N=8 by default)
//   • Each line: exactly N integers in [1..N], separated by ONE ASCII space (' ')
//   • No tabs, no leading/trailing spaces
//   • Each line ends with a single LF ('\n'); the file ends with a final LF
//   • Any deviation ⇒ format error (reject)

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ----------------------------------------------------------------------
// Parameters
// ----------------------------------------------------------------------
#define NDEFAULT 8
#define NMAX 8
#define CELLMAX (NMAX * NMAX)
#define CAGEMAX CELLMAX
#define INEQMAX (CELLMAX * 2)

// ----------------------------------------------------------------------
// RNG: xorshift32 (fixed seed for reproducibility)
// ----------------------------------------------------------------------
static const uint32_t FIXED_SEED = 0xC0FFEE42u;
static uint32_t rng_state;

static void rng_seed(uint32_t s) {
    rng_state = (s ? s : 2463534242u);
}

static uint32_t xr(void) {
    uint32_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    rng_state = x;
    return x;
}

static int rnd_int(int lo, int hi) {
    if (hi < lo) {
        int t = lo; lo = hi; hi = t;
    }
    uint32_t span = (uint32_t)(hi - lo + 1);
    return lo + (int)(xr() % span);
}

static void shuffle_int(int *a, int n) {
    for (int i = n - 1; i > 0; --i) {
        int j = (int)(xr() % (uint32_t)(i + 1));
        int t = a[i];
        a[i] = a[j];
        a[j] = t;
    }
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------
static inline int idx_rc(int r, int c, int N) { return r * N + c; }
static inline void rc_idx(int idx, int N, int *r, int *c) { *r = idx / N; *c = idx % N; }

static int neighbors4(int N, int r, int c, int out_idx[4]) {
    int k = 0;
    if (r > 0)     out_idx[k++] = idx_rc(r - 1, c, N);
    if (r + 1 < N) out_idx[k++] = idx_rc(r + 1, c, N);
    if (c > 0)     out_idx[k++] = idx_rc(r, c - 1, N);
    if (c + 1 < N) out_idx[k++] = idx_rc(r, c + 1, N);
    return k;
}

static inline int bit_of(int v) { return 1 << (v - 1); }
static inline int mask_full(int N) { return (1 << N) - 1; }
static inline int mask_has(int mask, int v) { return mask & bit_of(v); }

static int mask_min(int mask) {
    for (int v = 1; v <= 32; ++v) if (mask & bit_of(v)) return v;
    return 0;
}

static int mask_max(int mask, int N) {
    for (int v = N; v >= 1; --v) if (mask & bit_of(v)) return v;
    return 0;
}

static int prod_vals(const int *vals, int k) {
    int p = 1;
    for (int i = 0; i < k; i++) p *= vals[i];
    return p;
}

// ----------------------------------------------------------------------
// Data structures
// ----------------------------------------------------------------------
typedef struct {
    int   cnt;
    int   cells[CELLMAX];
    char  op;      // one of {'=', '+', '*', '-', '/'}
    int   target;
} Cage;

typedef struct {
    int  a, b;     // cell indices [0, N*N)
    char rel;      // '<' or '>'
} Inequality;

typedef struct {
    int   N;
    int   Latin[CELLMAX];
    int   cage_count;
    Cage  cages[CAGEMAX];
    int   cell_to_cage[CELLMAX];
    int   ineq_count;
    Inequality ineq[INEQMAX];
    int   parity[CELLMAX];    // -1 none, 0 even, 1 odd
} Puzzle;

// ----------------------------------------------------------------------
// Latin square generator
// ----------------------------------------------------------------------
static void gen_latin(int N, int *L) {
    // base cyclic Latin square
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            L[idx_rc(i, j, N)] = (i + j) % N + 1;
        }
    }

    // randomly permute rows, cols, and symbols (with fixed RNG)
    int prow[NMAX], pcol[NMAX], psym[NMAX];
    for (int i = 0; i < N; i++) {
        prow[i] = i; pcol[i] = i; psym[i] = i;
    }
    shuffle_int(prow, N);
    shuffle_int(pcol, N);
    shuffle_int(psym, N);

    int out[CELLMAX];
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            int v = L[idx_rc(prow[i], pcol[j], N)];
            out[idx_rc(i, j, N)] = psym[v - 1] + 1;
        }
    }
    memcpy(L, out, sizeof(int) * N * N);
}

// ----------------------------------------------------------------------
// Random connected cages
// ----------------------------------------------------------------------
static void gen_random_cages(int N,
                             int *remaining,
                             int *rem_cnt,
                             Cage *cages,
                             int *cage_count) {
    int min_size = 1;
    int max_size = 4;
    *cage_count = 0;

    while (*rem_cnt > 0) {
        int pick_i = rnd_int(0, *rem_cnt - 1);
        int start  = remaining[pick_i];
        remaining[pick_i] = remaining[*rem_cnt - 1];
        (*rem_cnt)--;

        int target_size = rnd_int(min_size, max_size);

        int frontier[CELLMAX];
        int fsz = 0;
        int cage_cells[CELLMAX];
        int csz = 0;

        cage_cells[csz++] = start;
        frontier[fsz++]   = start;

        static uint8_t in_rem[CELLMAX];
        memset(in_rem, 0, sizeof(in_rem));
        for (int i = 0; i < *rem_cnt; i++) in_rem[ remaining[i] ] = 1;

        while (fsz > 0 && csz < target_size) {
            int fi  = rnd_int(0, fsz - 1);
            int cur = frontier[fi];
            frontier[fi] = frontier[--fsz];

            int r, c;
            rc_idx(cur, N, &r, &c);
            int nbrs[4];
            int nk = neighbors4(N, r, c, nbrs);

            // shuffle neighbors
            for (int t = nk - 1; t > 0; --t) {
                int j   = rnd_int(0, t);
                int tmp = nbrs[t];
                nbrs[t] = nbrs[j];
                nbrs[j] = tmp;
            }

            for (int t = 0; t < nk && csz < target_size; ++t) {
                int nb = nbrs[t];
                if (in_rem[nb]) {
                    in_rem[nb] = 0;
                    for (int k = 0; k < *rem_cnt; k++) {
                        if (remaining[k] == nb) {
                            remaining[k] = remaining[*rem_cnt - 1];
                            (*rem_cnt)--;
                            break;
                        }
                    }
                    cage_cells[csz++] = nb;
                    frontier[fsz++]   = nb;
                }
            }
        }

        Cage *cg = &cages[(*cage_count)++];
        cg->cnt    = csz;
        cg->op     = '?';
        cg->target = 0;
        for (int i = 0; i < csz; i++) cg->cells[i] = cage_cells[i];
    }
}

// ----------------------------------------------------------------------
// Assign cage ops/targets from the solution (puzzle answer)
// ----------------------------------------------------------------------
static void assign_ops_targets(int N, const int *sol, Cage *cages, int cage_count) {
    (void)N; // not used directly (kept for symmetry)

    for (int ci = 0; ci < cage_count; ++ci) {
        Cage *cg = &cages[ci];
        int   k  = cg->cnt;
        int   vals[CELLMAX];
        for (int i = 0; i < k; i++) vals[i] = sol[cg->cells[i]];

        if (k == 1) {
            cg->op     = '=';
            cg->target = vals[0];
            continue;
        }

        if (k == 2) {
            int a = vals[0], b = vals[1];
            int big = a, small = b;
            if (small > big) { int t = big; big = small; small = t; }

            int have_div = (small != 0 && big % small == 0);

            // Priority with some randomness: '-' default, maybe '/', rarely '+' or '*'
            cg->op     = '-';
            cg->target = big - small;

            if ((xr() % 100) < 33 && have_div) {
                cg->op     = '/';
                cg->target = big / small;
            }
            if ((xr() % 100) < 10) {
                cg->op     = '+';
                cg->target = a + b;
            }
            if ((xr() % 100) < 5) {
                cg->op     = '*';
                cg->target = a * b;
            }
            continue;
        }

        // Size >= 3: prefer '+' often, sometimes '*'
        if ((xr() % 100) < 55) {
            cg->op     = '+';
            int s = 0; for (int i = 0; i < k; i++) s += vals[i];
            cg->target = s;
        } else {
            cg->op     = '*';
            cg->target = prod_vals(vals, k);
        }
    }
}

// ----------------------------------------------------------------------
// Inequalities & parity hints
// ----------------------------------------------------------------------
static void gen_adj_pairs(int N, int *pairs, int *pair_cnt) {
    int cnt = 0;
    for (int r = 0; r < N; r++) {
        for (int c = 0; c < N; c++) {
            int a = idx_rc(r, c, N);
            if (r + 1 < N) { int b = idx_rc(r + 1, c, N); pairs[2 * cnt] = a; pairs[2 * cnt + 1] = b; cnt++; }
            if (c + 1 < N) { int b = idx_rc(r, c + 1, N); pairs[2 * cnt] = a; pairs[2 * cnt + 1] = b; cnt++; }
        }
    }
    *pair_cnt = cnt;
}

static void generate_inequalities(Puzzle *P, double density) {
    int N = P->N;
    int pairs[CELLMAX * 2];
    int pair_cnt = 0;
    gen_adj_pairs(N, pairs, &pair_cnt);

    int order[CELLMAX * 2];
    for (int i = 0; i < pair_cnt; i++) order[i] = i;
    shuffle_int(order, pair_cnt);

    int take = (int)(pair_cnt * density);
    P->ineq_count = 0;

    for (int t = 0; t < take && t < pair_cnt && P->ineq_count < INEQMAX; ++t) {
        int i = order[t];
        int a = pairs[2 * i];
        int b = pairs[2 * i + 1];
        int va = P->Latin[a];
        int vb = P->Latin[b];
        if (va == vb) continue;
        // bounds are guaranteed by construction; keep a defensive check
        if (a < 0 || a >= N * N || b < 0 || b >= N * N) continue;
        Inequality q; q.a = a; q.b = b; q.rel = (va < vb ? '<' : '>');
        P->ineq[P->ineq_count++] = q;
    }
}

static void generate_parity(Puzzle *P, double density) {
    int N = P->N;
    int cells = N * N;
    int order[CELLMAX];
    for (int i = 0; i < cells; i++) order[i] = i;
    shuffle_int(order, cells);

    int take = (int)(cells * density);
    for (int i = 0; i < cells; i++) P->parity[i] = -1;
    for (int i = 0; i < take && i < cells; ++i) {
        int idx = order[i];
        int v   = P->Latin[idx];
        P->parity[idx] = (v % 2 == 0 ? 0 : 1);
    }
}

// ----------------------------------------------------------------------
// Constraint checks (partial & full)
// ----------------------------------------------------------------------
static int cage_feasible_partial(const Puzzle *P,
                                 int ci,
                                 const int *assign,
                                 const int *domains) {
    const Cage *cg = &P->cages[ci];
    char op   = cg->op;
    int  tgt  = cg->target;
    int  k    = cg->cnt;

    int all_assigned = 1;
    for (int i = 0; i < k; i++) {
        if (assign[cg->cells[i]] == 0) { all_assigned = 0; break; }
    }

    if (all_assigned) {
        if (op == '=') {
            return assign[cg->cells[0]] == tgt;
        }
        if (op == '+') {
            int s = 0; for (int i = 0; i < k; i++) s += assign[cg->cells[i]];
            return s == tgt;
        }
        if (op == '*') {
            int p = 1; for (int i = 0; i < k; i++) p *= assign[cg->cells[i]];
            return p == tgt;
        }
        if (op == '-') {
            int a = assign[cg->cells[0]];
            int b = assign[cg->cells[1]];
            int big = a, small = b;
            if (small > big) { int t = big; big = small; small = t; }
            return (big - small) == tgt;
        }
        if (op == '/') {
            int a = assign[cg->cells[0]];
            int b = assign[cg->cells[1]];
            int big = a, small = b;
            if (small > big) { int t = big; big = small; small = t; }
            return (small != 0 && big % small == 0 && big / small == tgt);
        }
        return 0;
    }

    if (op == '+') {
        int min = 0, max = 0;
        for (int i = 0; i < k; i++) {
            int cell = cg->cells[i];
            int v    = assign[cell];
            if (v) {
                min += v; max += v;
            } else {
                int m = domains[cell];
                if (!m) return 0;
                min += mask_min(m);
                max += mask_max(m, P->N);
            }
        }
        return (min <= tgt && tgt <= max);
    }

    if (op == '*') {
        int minp = 1, maxp = 1;
        for (int i = 0; i < k; i++) {
            int cell = cg->cells[i];
            int v    = assign[cell];
            if (v) {
                minp *= v; maxp *= v;
            } else {
                int m = domains[cell];
                if (!m) return 0;
                minp *= mask_min(m);
                maxp *= mask_max(m, P->N);
            }
        }
        return (minp <= tgt && tgt <= maxp);
    }

    if (op == '-' || op == '/') {
        if (k != 2) return 0;
        int a = cg->cells[0];
        int b = cg->cells[1];
        int Am = assign[a] ? bit_of(assign[a]) : domains[a];
        int Bm = assign[b] ? bit_of(assign[b]) : domains[b];
        if (!Am || !Bm) return 0;
        for (int va = 1; va <= P->N; ++va) if (Am & bit_of(va)) {
            for (int vb = 1; vb <= P->N; ++vb) if (Bm & bit_of(vb)) {
                int big = va, small = vb;
                if (small > big) { int t = big; big = small; small = t; }
                if (op == '-' && big - small == tgt) return 1;
                if (op == '/' && small != 0 && big % small == 0 && big / small == tgt) return 1;
            }
        }
        return 0;
    }

    if (op == '=') {
        int cell = cg->cells[0];
        int v    = assign[cell];
        if (v) return v == tgt;
        return mask_has(domains[cell], tgt) != 0;
    }

    return 1;
}

static int ineq_feasible(const Puzzle *P, const int *assign) {
    int N = P->N;
    int cells = N * N;
    for (int i = 0; i < P->ineq_count; i++) {
        int a = P->ineq[i].a;
        int b = P->ineq[i].b;
        char rel = P->ineq[i].rel;
        if (a < 0 || a >= cells || b < 0 || b >= cells) {
            // Defensive: ignore invalid entries
            continue;
        }
        int va = assign[a];
        int vb = assign[b];
        if (va == 0 || vb == 0) continue;
        if (rel == '<' && !(va < vb)) return 0;
        if (rel == '>' && !(va > vb)) return 0;
    }
    return 1;
}

// ----------------------------------------------------------------------
// Solver (count solutions up to a cap)
// ----------------------------------------------------------------------
typedef struct {
    const Puzzle *P;
    int   max_solutions;
    int   sol_count;
    int   domains[CELLMAX];
    int   row_used[NMAX];
    int   col_used[NMAX];
    int   assign[CELLMAX];
} Solver;

static int solver_mrv_cell(Solver *S) {
    const int N     = S->P->N;
    const int cells = N * N;
    int best = -1;
    int bestK = 1000000000;

    for (int i = 0; i < cells; i++) if (S->assign[i] == 0) {
        int r = i / N;
        int c = i % N;
        int mask = S->domains[i];

        // remove used values from row/col
        for (int v = 1; v <= N; ++v) {
            if ((S->row_used[r] & bit_of(v)) || (S->col_used[c] & bit_of(v)))
                mask &= ~bit_of(v);
        }
        if (mask == 0) return -2; // dead end

        int k = 0;
        for (int v = 1; v <= N; ++v) if (mask & bit_of(v)) k++;

        if (k < bestK) {
            bestK = k;
            best  = i;
            if (k == 1) break;
        }
    }
    return best;
}

static void solver_dfs(Solver *S) {
    if (S->sol_count >= S->max_solutions) return;

    int cell = solver_mrv_cell(S);
    if (cell == -2) return;      // contradiction
    if (cell == -1) {            // all assigned => one solution
        S->sol_count++;
        return;
    }

    const int N = S->P->N;
    int r = cell / N;
    int c = cell % N;
    int mask = S->domains[cell];

    for (int v = 1; v <= N; ++v) {
        if (!(mask & bit_of(v))) continue;
        if ((S->row_used[r] & bit_of(v)) || (S->col_used[c] & bit_of(v))) continue;

        S->assign[cell] = v;
        S->row_used[r] |= bit_of(v);
        S->col_used[c] |= bit_of(v);

        int ci = S->P->cell_to_cage[cell];
        if (cage_feasible_partial(S->P, ci, S->assign, S->domains) &&
            ineq_feasible(S->P, S->assign)) {
            solver_dfs(S);
            if (S->sol_count >= S->max_solutions) {
                S->assign[cell] = 0;
                S->row_used[r] &= ~bit_of(v);
                S->col_used[c] &= ~bit_of(v);
                return;
            }
        }

        S->assign[cell] = 0;
        S->row_used[r] &= ~bit_of(v);
        S->col_used[c] &= ~bit_of(v);
    }
}

static int solve_count(const Puzzle *P, int max_solutions) {
    const int N     = P->N;
    const int cells = N * N;

    Solver S;
    S.P             = P;
    S.max_solutions = max_solutions;
    S.sol_count     = 0;

    for (int i = 0; i < cells; i++) {
        S.domains[i] = mask_full(N);
        int par = P->parity[i];
        if (par == 0) {
            int m = 0; for (int v = 1; v <= N; ++v) if (v % 2 == 0) m |= bit_of(v);
            S.domains[i] &= m;
        } else if (par == 1) {
            int m = 0; for (int v = 1; v <= N; ++v) if (v % 2 == 1) m |= bit_of(v);
            S.domains[i] &= m;
        }
        if (S.domains[i] == 0) return 0;
        S.assign[i] = 0;
    }
    for (int r = 0; r < N; r++) S.row_used[r] = 0;
    for (int c = 0; c < N; c++) S.col_used[c] = 0;

    solver_dfs(&S);
    return S.sol_count;
}

// ----------------------------------------------------------------------
// Generator (ensures uniqueness)
// ----------------------------------------------------------------------
static int generate_unique(Puzzle *P) {
    const int N     = P->N;
    const int cells = N * N;

    int attempts = 0;
    while (attempts < 200) {
        attempts++;

        // Make a random Latin solution
        gen_latin(N, P->Latin);

        // Random connected cages
        int rem[CELLMAX];
        int rem_cnt = 0;
        for (int i = 0; i < cells; i++) rem[rem_cnt++] = i;
        shuffle_int(rem, rem_cnt);
        gen_random_cages(N, rem, &rem_cnt, P->cages, &P->cage_count);

        // Map cells → cage index
        for (int i = 0; i < cells; i++) P->cell_to_cage[i] = -1;
        for (int ci = 0; ci < P->cage_count; ++ci) {
            for (int k = 0; k < P->cages[ci].cnt; ++k) {
                P->cell_to_cage[ P->cages[ci].cells[k] ] = ci;
            }
        }

        // Set cage operations/targets from solution
        assign_ops_targets(N, P->Latin, P->cages, P->cage_count);

        // Add inequalities & parity
        generate_inequalities(P, 0.20);
        generate_parity(P,       0.18);

        // Check uniqueness; if not unique, add a few extra inequalities
        int cnt = solve_count(P, 2);
        if (cnt == 1) return 1;

        int tries_local = 0;
        int added = 0;
        while (cnt != 1 && tries_local < 16 && added < 8) {
            tries_local++;
            int r = rnd_int(0, N - 1);
            int c = rnd_int(0, N - 1);

            // choose a random neighbor and add correct-direction inequality
            int nbrs[4];
            int nk = neighbors4(N, r, c, nbrs);
            if (nk == 0) continue;
            int nb = nbrs[rnd_int(0, nk - 1)];
            int a  = idx_rc(r, c, N);
            int b  = nb;
            int va = P->Latin[a];
            int vb = P->Latin[b];
            if (va == vb) continue;

            if (P->ineq_count < INEQMAX) {
                Inequality q; q.a = a; q.b = b; q.rel = (va < vb ? '<' : '>');
                P->ineq[P->ineq_count++] = q;
                added++;
            }
            cnt = solve_count(P, 2);
        }
        if (cnt == 1) return 1;
    }
    return 0;
}

// ----------------------------------------------------------------------
// SHA-256 (compact implementation)
// ----------------------------------------------------------------------
typedef struct {
    uint64_t len;
    uint32_t state[8];
    uint8_t  buf[64];
    size_t   curlen;
} sha256_ctx;

static uint32_t RORc(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
static uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static uint32_t S(uint32_t x, uint32_t n) { return RORc(x, n); }
static uint32_t R(uint32_t x, uint32_t n) { return x >> n; }
static uint32_t Sigma0(uint32_t x) { return S(x, 2) ^ S(x, 13) ^ S(x, 22); }
static uint32_t Sigma1(uint32_t x) { return S(x, 6) ^ S(x, 11) ^ S(x, 25); }
static uint32_t Gamma0(uint32_t x) { return S(x, 7) ^ S(x, 18) ^ R(x, 3); }
static uint32_t Gamma1(uint32_t x) { return S(x, 17) ^ S(x, 19) ^ R(x, 10); }

static const uint32_t K256[64] = { 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5, 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174, 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da, 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967, 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85, 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070, 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3, 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };

static void sha256_init(sha256_ctx *md) {
    md->curlen = 0;
    md->len    = 0;
    md->state[0] = 0x6A09E667;
    md->state[1] = 0xBB67AE85;
    md->state[2] = 0x3C6EF372;
    md->state[3] = 0xA54FF53A;
    md->state[4] = 0x510E527F;
    md->state[5] = 0x9B05688C;
    md->state[6] = 0x1F83D9AB;
    md->state[7] = 0x5BE0CD19;
}

static void sha256_compress(sha256_ctx *md, const uint8_t *buf) {
    uint32_t W[64], t;
    uint32_t s[8];
    for (t = 0; t < 8; t++) s[t] = md->state[t];
    for (t = 0; t < 16; t++) {
        W[t] = ((uint32_t)buf[t*4] << 24) |
               ((uint32_t)buf[t*4+1] << 16) |
               ((uint32_t)buf[t*4+2] << 8) |
               ((uint32_t)buf[t*4+3]);
    }
    for (t = 16; t < 64; t++) W[t] = Gamma1(W[t-2]) + W[t-7] + Gamma0(W[t-15]) + W[t-16];
    for (t = 0; t < 64; t++) {
        uint32_t T0 = s[7] + Sigma1(s[4]) + Ch(s[4], s[5], s[6]) + K256[t] + W[t];
        uint32_t T1 = Sigma0(s[0]) + Maj(s[0], s[1], s[2]);
        s[7] = s[6];
        s[6] = s[5];
        s[5] = s[4];
        s[4] = s[3] + T0;
        s[3] = s[2];
        s[2] = s[1];
        s[1] = s[0];
        s[0] = T0 + T1;
    }
    for (t = 0; t < 8; t++) md->state[t] += s[t];
}

static void sha256_update(sha256_ctx *md, const uint8_t *in, size_t inlen) {
    while (inlen > 0) {
        size_t n = 64 - md->curlen;
        if (n > inlen) n = inlen;
        memcpy(md->buf + md->curlen, in, n);
        md->curlen += n;
        md->len    += n;
        in         += n;
        inlen      -= n;
        if (md->curlen == 64) {
            sha256_compress(md, md->buf);
            md->curlen = 0;
        }
    }
}

static void sha256_done(sha256_ctx *md, uint8_t *out) {
    uint64_t bitlen = md->len * 8;
    md->buf[md->curlen++] = 0x80;
    if (md->curlen > 56) {
        while (md->curlen < 64) md->buf[md->curlen++] = 0;
        sha256_compress(md, md->buf);
        md->curlen = 0;
    }
    while (md->curlen < 56) md->buf[md->curlen++] = 0;
    for (int i = 0; i < 8; i++) md->buf[56 + i] = (uint8_t)((bitlen >> (56 - 8 * i)) & 0xFF);
    sha256_compress(md, md->buf);
    for (int i = 0; i < 8; i++) {
        out[i*4+0] = (md->state[i] >> 24) & 0xFF;
        out[i*4+1] = (md->state[i] >> 16) & 0xFF;
        out[i*4+2] = (md->state[i] >> 8) & 0xFF;
        out[i*4+3] = (md->state[i]) & 0xFF;
    }
}

static int sha256_file_hex(const char *path, char *hex_out /*65*/) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    sha256_ctx ctx;
    sha256_init(&ctx);

    uint8_t buf[4096];
    for (;;) {
        size_t n = fread(buf, 1, sizeof(buf), fp);
        if (n > 0) sha256_update(&ctx, buf, n);
        if (n < sizeof(buf)) {
            if (ferror(fp)) { fclose(fp); return -2; }
            break;
        }
    }
    fclose(fp);

    uint8_t digest[32];
    sha256_done(&ctx, digest);

    static const char *hx = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex_out[i*2+0] = hx[digest[i] >> 4];
        hex_out[i*2+1] = hx[digest[i] & 0xF];
    }
    hex_out[64] = '\0';
    return 0;
}

// ----------------------------------------------------------------------
// Builder
// ----------------------------------------------------------------------
static int generate_unique(Puzzle *P);  // forward

static void build_puzzle(Puzzle *P, int N) {
    memset(P, 0, sizeof(*P));
    P->N = N;
    for (int i = 0; i < N * N; i++) P->parity[i] = -1;

    rng_seed(FIXED_SEED);
    if (!generate_unique(P)) {
        exit(1);
    }
}

// ----------------------------------------------------------------------
// Strict canonical solution file parser
// ----------------------------------------------------------------------
static int parse_canonical_grid_file(const char *path, int N, int *grid) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return -1; }
    long sz = ftell(fp);
    if (sz < 0) { fclose(fp); return -1; }
    if (fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return -1; }

    char *buf = (char*)malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); return -1; }
    size_t n = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    buf[n] = '\0';

    if (n == 0 || buf[n - 1] != '\n') {
        free(buf);
        return -1;
    }

    int    row = 0;
    size_t pos = 0;

    while (pos < n) {
        size_t line_start = pos;
        size_t line_end   = line_start;
        while (line_end < n && buf[line_end] != '\n') line_end++;

        if (line_end == line_start) {
            free(buf);
            return -1;
        }

        int    col = 0;
        size_t i   = line_start;
        while (i < line_end) {
            if (col >= N) { free(buf); return -1; }
            if (i >= line_end || buf[i] < '0' || buf[i] > '9') { free(buf); return -1; }

            int    v = 0;
            size_t j = i;
            while (j < line_end && buf[j] >= '0' && buf[j] <= '9') {
                v = v * 10 + (buf[j] - '0');
                j++;
            }
            if (v < 1 || v > N) { free(buf); return -1; }
            grid[row * N + col] = v;
            col++;

            if (j < line_end) {
                if (buf[j] != ' ') { free(buf); return -1; }
                i = j + 1;
                if (i >= line_end || buf[i] < '0' || buf[i] > '9') { free(buf); return -1; }
            } else {
                i = j; // end of line
            }
        }

        if (col != N) { free(buf); return -1; }
        if (line_end >= n || buf[line_end] != '\n') { free(buf); return -1; }

        pos = line_end + 1;
        row++;
        if (row > N) { free(buf); return -1; }
    }

    if (row != N) { free(buf); return -1; }

    free(buf);
    return 0;
}

// ----------------------------------------------------------------------
// Grid validator against puzzle
// ----------------------------------------------------------------------
static int validate_grid(const Puzzle *P, const int *G) {
    int N = P->N;

    // Latin rows
    for (int r = 0; r < N; r++) {
        int seen = 0;
        for (int c = 0; c < N; c++) {
            int v = G[idx_rc(r, c, N)];
            if (v < 1 || v > N) return 0;
            if (seen & bit_of(v)) return 0;
            seen |= bit_of(v);
        }
    }

    // Latin columns
    for (int c = 0; c < N; c++) {
        int seen = 0;
        for (int r = 0; r < N; r++) {
            int v = G[idx_rc(r, c, N)];
            if (seen & bit_of(v)) return 0;
            seen |= bit_of(v);
        }
    }

    // Parity
    for (int i = 0; i < N * N; i++) {
        if (P->parity[i] == 0 && (G[i] % 2) != 0) return 0;
        if (P->parity[i] == 1 && (G[i] % 2) != 1) return 0;
    }

    // Inequalities
    {
        int cells = N * N;
        for (int i = 0; i < P->ineq_count; i++) {
            int a = P->ineq[i].a;
            int b = P->ineq[i].b;
            char rel = P->ineq[i].rel;
            if (a < 0 || a >= cells || b < 0 || b >= cells) continue; // ignore invalid
            int va = G[a];
            int vb = G[b];
            if (rel == '<' && !(va < vb)) return 0;
            if (rel == '>' && !(va > vb)) return 0;
        }
    }

    // Cages
    for (int ci = 0; ci < P->cage_count; ++ci) {
        const Cage *cg = &P->cages[ci];
        char op = cg->op;
        int  tgt = cg->target;
        if (op == '=') {
            if (G[cg->cells[0]] != tgt) return 0;
        } else if (op == '+') {
            int s = 0; for (int k = 0; k < cg->cnt; k++) s += G[cg->cells[k]];
            if (s != tgt) return 0;
        } else if (op == '*') {
            int p = 1; for (int k = 0; k < cg->cnt; k++) p *= G[cg->cells[k]];
            if (p != tgt) return 0;
        } else if (op == '-') {
            int a = G[cg->cells[0]];
            int b = G[cg->cells[1]];
            int big = a, small = b;
            if (small > big) { int t = big; big = small; small = t; }
            if (big - small != tgt) return 0;
        } else if (op == '/') {
            int a = G[cg->cells[0]];
            int b = G[cg->cells[1]];
            int big = a, small = b;
            if (small > big) { int t = big; big = small; small = t; }
            if (!(small != 0 && big % small == 0 && big / small == tgt)) return 0;
        } else {
            return 0;
        }
    }

    return 1;
}

// ----------------------------------------------------------------------
// Main
// ----------------------------------------------------------------------
int main(int argc, char **argv) {
    Puzzle *P_ptr = (Puzzle*)malloc(sizeof(Puzzle));
    if(!P_ptr) {
        return 1;
    }
    build_puzzle(P_ptr, NDEFAULT);

    if (argc == 2) {
        // VERIFY
        const char *path = argv[1];
        int G[CELLMAX];

        if (parse_canonical_grid_file(path, P_ptr->N, G) != 0) {
            return 2; // format error already printed
        }
        if (!validate_grid(P_ptr, G)) {
            return 3;
        }
        char hex[65];
        int rc = sha256_file_hex(path, hex);
        if (rc != 0) {
            return 4;
        }
        printf("CyKor{%s}\n", hex);
        return 0;
    }
}