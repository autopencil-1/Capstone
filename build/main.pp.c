

























#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>




#define NDEFAULT 8
#define NMAX 8
#define CELLMAX (NMAX * NMAX)
#define CAGEMAX CELLMAX
#define INEQMAX (CELLMAX * 2)




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
    if (hi < lo) { goto IF_T_00001; }
goto IF_E_00002;
IF_T_00001: {

        int t = lo; lo = hi; hi = t;
    
}
IF_E_00002:

    uint32_t span = (uint32_t)(hi - lo + 1);
    return lo + (int)(xr() % span);
}

static void shuffle_int(int *a, int n) {
    {
int i = n - 1;
F_LOOP_00003:
if (i > 0) { goto F_BODY_00004; }
goto F_END_00006;
F_BODY_00004: {

        int j = (int)(xr() % (uint32_t)(i + 1));
        int t = a[i];
        a[i] = a[j];
        a[j] = t;
    
}
F_STEP_00005:
--i;
goto F_LOOP_00003;
F_END_00006:
}

}




static inline int idx_rc(int r, int c, int N) { return r * N + c; }
static inline void rc_idx(int idx, int N, int *r, int *c) { *r = idx / N; *c = idx % N; }

static int neighbors4(int N, int r, int c, int out_idx[4]) {
    int k = 0;
    if (r > 0) { goto IF_T_00007; }
goto IF_E_00008;
IF_T_00007: {
out_idx[k++] = idx_rc(r - 1, c, N);
}
IF_E_00008:

    if (r + 1 < N) { goto IF_T_00009; }
goto IF_E_00010;
IF_T_00009: {
out_idx[k++] = idx_rc(r + 1, c, N);
}
IF_E_00010:

    if (c > 0) { goto IF_T_00011; }
goto IF_E_00012;
IF_T_00011: {
out_idx[k++] = idx_rc(r, c - 1, N);
}
IF_E_00012:

    if (c + 1 < N) { goto IF_T_00013; }
goto IF_E_00014;
IF_T_00013: {
out_idx[k++] = idx_rc(r, c + 1, N);
}
IF_E_00014:

    return k;
}

static inline int bit_of(int v) { return 1 << (v - 1); }
static inline int mask_full(int N) { return (1 << N) - 1; }
static inline int mask_has(int mask, int v) { return mask & bit_of(v); }

static int mask_min(int mask) {
    {
int v = 1;
F_LOOP_00015:
if (v <= 32) { goto F_BODY_00016; }
goto F_END_00018;
F_BODY_00016: {
if (mask & bit_of(v)) { goto IF_T_00019; }
goto IF_E_00020;
IF_T_00019: {
return v;
}
IF_E_00020:

}
F_STEP_00017:
++v;
goto F_LOOP_00015;
F_END_00018:
}

    return 0;
}

static int mask_max(int mask, int N) {
    {
int v = N;
F_LOOP_00021:
if (v >= 1) { goto F_BODY_00022; }
goto F_END_00024;
F_BODY_00022: {
if (mask & bit_of(v)) { goto IF_T_00025; }
goto IF_E_00026;
IF_T_00025: {
return v;
}
IF_E_00026:

}
F_STEP_00023:
--v;
goto F_LOOP_00021;
F_END_00024:
}

    return 0;
}

static int prod_vals(const int *vals, int k) {
    int p = 1;
    {
int i = 0;
F_LOOP_00027:
if (i < k) { goto F_BODY_00028; }
goto F_END_00030;
F_BODY_00028: {
p *= vals[i];
}
F_STEP_00029:
i++;
goto F_LOOP_00027;
F_END_00030:
}

    return p;
}




typedef struct {
    int   cnt;
    int   cells[CELLMAX];
    char  op;      
    int   target;
} Cage;

typedef struct {
    int  a, b;     
    char rel;      
} Inequality;

typedef struct {
    int   N;
    int   Latin[CELLMAX];
    int   cage_count;
    Cage  cages[CAGEMAX];
    int   cell_to_cage[CELLMAX];
    int   ineq_count;
    Inequality ineq[INEQMAX];
    int   parity[CELLMAX];    
} Puzzle;




static void gen_latin(int N, int *L) {
    
    {
int i = 0;
F_LOOP_00031:
if (i < N) { goto F_BODY_00032; }
goto F_END_00034;
F_BODY_00032: {

        {
int j = 0;
F_LOOP_00035:
if (j < N) { goto F_BODY_00036; }
goto F_END_00038;
F_BODY_00036: {

            L[idx_rc(i, j, N)] = (i + j) % N + 1;
        
}
F_STEP_00037:
j++;
goto F_LOOP_00035;
F_END_00038:
}

    
}
F_STEP_00033:
i++;
goto F_LOOP_00031;
F_END_00034:
}


    
    int prow[NMAX], pcol[NMAX], psym[NMAX];
    {
int i = 0;
F_LOOP_00039:
if (i < N) { goto F_BODY_00040; }
goto F_END_00042;
F_BODY_00040: {

        prow[i] = i; pcol[i] = i; psym[i] = i;
    
}
F_STEP_00041:
i++;
goto F_LOOP_00039;
F_END_00042:
}

    shuffle_int(prow, N);
    shuffle_int(pcol, N);
    shuffle_int(psym, N);

    int out[CELLMAX];
    {
int i = 0;
F_LOOP_00043:
if (i < N) { goto F_BODY_00044; }
goto F_END_00046;
F_BODY_00044: {

        {
int j = 0;
F_LOOP_00047:
if (j < N) { goto F_BODY_00048; }
goto F_END_00050;
F_BODY_00048: {

            int v = L[idx_rc(prow[i], pcol[j], N)];
            out[idx_rc(i, j, N)] = psym[v - 1] + 1;
        
}
F_STEP_00049:
j++;
goto F_LOOP_00047;
F_END_00050:
}

    
}
F_STEP_00045:
i++;
goto F_LOOP_00043;
F_END_00046:
}

    memcpy(L, out, sizeof(int) * N * N);
}




static void gen_random_cages(int N,
                             int *remaining,
                             int *rem_cnt,
                             Cage *cages,
                             int *cage_count) {
    int min_size = 1;
    int max_size = 4;
    *cage_count = 0;

    
W_LOOP_00051:
if (*rem_cnt > 0) { goto W_BODY_00052; }
goto W_END_00053;
W_BODY_00052: {

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
        {
int i = 0;
F_LOOP_00054:
if (i < *rem_cnt) { goto F_BODY_00055; }
goto F_END_00057;
F_BODY_00055: {
in_rem[ remaining[i] ] = 1;
}
F_STEP_00056:
i++;
goto F_LOOP_00054;
F_END_00057:
}


        
W_LOOP_00058:
if (fsz > 0 && csz < target_size) { goto W_BODY_00059; }
goto W_END_00060;
W_BODY_00059: {

            int fi  = rnd_int(0, fsz - 1);
            int cur = frontier[fi];
            frontier[fi] = frontier[--fsz];

            int r, c;
            rc_idx(cur, N, &r, &c);
            int nbrs[4];
            int nk = neighbors4(N, r, c, nbrs);

            
            {
int t = nk - 1;
F_LOOP_00061:
if (t > 0) { goto F_BODY_00062; }
goto F_END_00064;
F_BODY_00062: {

                int j   = rnd_int(0, t);
                int tmp = nbrs[t];
                nbrs[t] = nbrs[j];
                nbrs[j] = tmp;
            
}
F_STEP_00063:
--t;
goto F_LOOP_00061;
F_END_00064:
}


            {
int t = 0;
F_LOOP_00065:
if (t < nk && csz < target_size) { goto F_BODY_00066; }
goto F_END_00068;
F_BODY_00066: {

                int nb = nbrs[t];
                if (in_rem[nb]) { goto IF_T_00075; }
goto IF_E_00076;
IF_T_00075: {

                    in_rem[nb] = 0;
                    {
int k = 0;
F_LOOP_00069:
if (k < *rem_cnt) { goto F_BODY_00070; }
goto F_END_00072;
F_BODY_00070: {

                        if (remaining[k] == nb) { goto IF_T_00073; }
goto IF_E_00074;
IF_T_00073: {

                            remaining[k] = remaining[*rem_cnt - 1];
                            (*rem_cnt)--;
                            goto F_END_00072;
                        
}
IF_E_00074:

                    
}
F_STEP_00071:
k++;
goto F_LOOP_00069;
F_END_00072:
}

                    cage_cells[csz++] = nb;
                    frontier[fsz++]   = nb;
                
}
IF_E_00076:

            
}
F_STEP_00067:
++t;
goto F_LOOP_00065;
F_END_00068:
}

        
}
goto W_LOOP_00058;
W_END_00060:


        Cage *cg = &cages[(*cage_count)++];
        cg->cnt    = csz;
        cg->op     = '?';
        cg->target = 0;
        {
int i = 0;
F_LOOP_00077:
if (i < csz) { goto F_BODY_00078; }
goto F_END_00080;
F_BODY_00078: {
cg->cells[i] = cage_cells[i];
}
F_STEP_00079:
i++;
goto F_LOOP_00077;
F_END_00080:
}

    
}
goto W_LOOP_00051;
W_END_00053:

}




static void assign_ops_targets(int N, const int *sol, Cage *cages, int cage_count) {
    (void)N; 

    {
int ci = 0;
F_LOOP_00081:
if (ci < cage_count) { goto F_BODY_00082; }
goto F_END_00084;
F_BODY_00082: {

        Cage *cg = &cages[ci];
        int   k  = cg->cnt;
        int   vals[CELLMAX];
        {
int i = 0;
F_LOOP_00085:
if (i < k) { goto F_BODY_00086; }
goto F_END_00088;
F_BODY_00086: {
vals[i] = sol[cg->cells[i]];
}
F_STEP_00087:
i++;
goto F_LOOP_00085;
F_END_00088:
}


        if (k == 1) { goto IF_T_00089; }
goto IF_E_00090;
IF_T_00089: {

            cg->op     = '=';
            cg->target = vals[0];
            goto F_STEP_00083;
        
}
IF_E_00090:


        if (k == 2) { goto IF_T_00099; }
goto IF_E_00100;
IF_T_00099: {

            int a = vals[0], b = vals[1];
            int big = a, small = b;
            if (small > big) { goto IF_T_00091; }
goto IF_E_00092;
IF_T_00091: {
 int t = big; big = small; small = t; 
}
IF_E_00092:


            int have_div = (small != 0 && big % small == 0);

            
            cg->op     = '-';
            cg->target = big - small;

            if ((xr() % 100) < 33 && have_div) { goto IF_T_00093; }
goto IF_E_00094;
IF_T_00093: {

                cg->op     = '/';
                cg->target = big / small;
            
}
IF_E_00094:

            if ((xr() % 100) < 10) { goto IF_T_00095; }
goto IF_E_00096;
IF_T_00095: {

                cg->op     = '+';
                cg->target = a + b;
            
}
IF_E_00096:

            if ((xr() % 100) < 5) { goto IF_T_00097; }
goto IF_E_00098;
IF_T_00097: {

                cg->op     = '*';
                cg->target = a * b;
            
}
IF_E_00098:

            goto F_STEP_00083;
        
}
IF_E_00100:


        
        if ((xr() % 100) < 55) { goto IF_T_00105; }
goto IF_F_00107;
IF_T_00105: {

            cg->op     = '+';
            int s = 0; {
int i = 0;
F_LOOP_00101:
if (i < k) { goto F_BODY_00102; }
goto F_END_00104;
F_BODY_00102: {
s += vals[i];
}
F_STEP_00103:
i++;
goto F_LOOP_00101;
F_END_00104:
}

            cg->target = s;
        
}
goto IF_E_00106;
IF_F_00107: {

            cg->op     = '*';
            cg->target = prod_vals(vals, k);
        
}
IF_E_00106:

    
}
F_STEP_00083:
++ci;
goto F_LOOP_00081;
F_END_00084:
}

}




static void gen_adj_pairs(int N, int *pairs, int *pair_cnt) {
    int cnt = 0;
    {
int r = 0;
F_LOOP_00108:
if (r < N) { goto F_BODY_00109; }
goto F_END_00111;
F_BODY_00109: {

        {
int c = 0;
F_LOOP_00112:
if (c < N) { goto F_BODY_00113; }
goto F_END_00115;
F_BODY_00113: {

            int a = idx_rc(r, c, N);
            if (r + 1 < N) { goto IF_T_00116; }
goto IF_E_00117;
IF_T_00116: {
 int b = idx_rc(r + 1, c, N); pairs[2 * cnt] = a; pairs[2 * cnt + 1] = b; cnt++; 
}
IF_E_00117:

            if (c + 1 < N) { goto IF_T_00118; }
goto IF_E_00119;
IF_T_00118: {
 int b = idx_rc(r, c + 1, N); pairs[2 * cnt] = a; pairs[2 * cnt + 1] = b; cnt++; 
}
IF_E_00119:

        
}
F_STEP_00114:
c++;
goto F_LOOP_00112;
F_END_00115:
}

    
}
F_STEP_00110:
r++;
goto F_LOOP_00108;
F_END_00111:
}

    *pair_cnt = cnt;
}

static void generate_inequalities(Puzzle *P, double density) {
    int N = P->N;
    int pairs[CELLMAX * 4];;
    int pair_cnt = 0;
    gen_adj_pairs(N, pairs, &pair_cnt);

    int order[CELLMAX * 2];
    {
int i = 0;
F_LOOP_00120:
if (i < pair_cnt) { goto F_BODY_00121; }
goto F_END_00123;
F_BODY_00121: {
order[i] = i;
}
F_STEP_00122:
i++;
goto F_LOOP_00120;
F_END_00123:
}

    shuffle_int(order, pair_cnt);

    int take = (int)(pair_cnt * density);
    P->ineq_count = 0;

    {
int t = 0;
F_LOOP_00124:
if (t < take && t < pair_cnt && P->ineq_count < INEQMAX) { goto F_BODY_00125; }
goto F_END_00127;
F_BODY_00125: {

        int i = order[t];
        int a = pairs[2 * i];
        int b = pairs[2 * i + 1];
        int va = P->Latin[a];
        int vb = P->Latin[b];
        if (va == vb) { goto IF_T_00128; }
goto IF_E_00129;
IF_T_00128: {
goto F_STEP_00126;
}
IF_E_00129:

        
        if (a < 0 || a >= N * N || b < 0 || b >= N * N) { goto IF_T_00130; }
goto IF_E_00131;
IF_T_00130: {
goto F_STEP_00126;
}
IF_E_00131:

        Inequality q; q.a = a; q.b = b; q.rel = (va < vb ? '<' : '>');
        P->ineq[P->ineq_count++] = q;
    
}
F_STEP_00126:
++t;
goto F_LOOP_00124;
F_END_00127:
}

}

static void generate_parity(Puzzle *P, double density) {
    int N = P->N;
    int cells = N * N;
    int order[CELLMAX];
    {
int i = 0;
F_LOOP_00132:
if (i < cells) { goto F_BODY_00133; }
goto F_END_00135;
F_BODY_00133: {
order[i] = i;
}
F_STEP_00134:
i++;
goto F_LOOP_00132;
F_END_00135:
}

    shuffle_int(order, cells);

    int take = (int)(cells * density);
    {
int i = 0;
F_LOOP_00136:
if (i < cells) { goto F_BODY_00137; }
goto F_END_00139;
F_BODY_00137: {
P->parity[i] = -1;
}
F_STEP_00138:
i++;
goto F_LOOP_00136;
F_END_00139:
}

    {
int i = 0;
F_LOOP_00140:
if (i < take && i < cells) { goto F_BODY_00141; }
goto F_END_00143;
F_BODY_00141: {

        int idx = order[i];
        int v   = P->Latin[idx];
        P->parity[idx] = (v % 2 == 0 ? 0 : 1);
    
}
F_STEP_00142:
++i;
goto F_LOOP_00140;
F_END_00143:
}

}




static int cage_feasible_partial(const Puzzle *P,
                                 int ci,
                                 const int *assign,
                                 const int *domains) {
    const Cage *cg = &P->cages[ci];
    char op   = cg->op;
    int  tgt  = cg->target;
    int  k    = cg->cnt;

    int all_assigned = 1;
    {
int i = 0;
F_LOOP_00144:
if (i < k) { goto F_BODY_00145; }
goto F_END_00147;
F_BODY_00145: {

        if (assign[cg->cells[i]] == 0) { goto IF_T_00148; }
goto IF_E_00149;
IF_T_00148: {
 all_assigned = 0; goto F_END_00147; 
}
IF_E_00149:

    
}
F_STEP_00146:
i++;
goto F_LOOP_00144;
F_END_00147:
}


    if (all_assigned) { goto IF_T_00172; }
goto IF_E_00173;
IF_T_00172: {

        if (op == '=') { goto IF_T_00150; }
goto IF_E_00151;
IF_T_00150: {

            return assign[cg->cells[0]] == tgt;
        
}
IF_E_00151:

        if (op == '+') { goto IF_T_00156; }
goto IF_E_00157;
IF_T_00156: {

            int s = 0; {
int i = 0;
F_LOOP_00152:
if (i < k) { goto F_BODY_00153; }
goto F_END_00155;
F_BODY_00153: {
s += assign[cg->cells[i]];
}
F_STEP_00154:
i++;
goto F_LOOP_00152;
F_END_00155:
}

            return s == tgt;
        
}
IF_E_00157:

        if (op == '*') { goto IF_T_00162; }
goto IF_E_00163;
IF_T_00162: {

            int p = 1; {
int i = 0;
F_LOOP_00158:
if (i < k) { goto F_BODY_00159; }
goto F_END_00161;
F_BODY_00159: {
p *= assign[cg->cells[i]];
}
F_STEP_00160:
i++;
goto F_LOOP_00158;
F_END_00161:
}

            return p == tgt;
        
}
IF_E_00163:

        if (op == '-') { goto IF_T_00166; }
goto IF_E_00167;
IF_T_00166: {

            int a = assign[cg->cells[0]];
            int b = assign[cg->cells[1]];
            int big = a, small = b;
            if (small > big) { goto IF_T_00164; }
goto IF_E_00165;
IF_T_00164: {
 int t = big; big = small; small = t; 
}
IF_E_00165:

            return (big - small) == tgt;
        
}
IF_E_00167:

        if (op == '/') { goto IF_T_00170; }
goto IF_E_00171;
IF_T_00170: {

            int a = assign[cg->cells[0]];
            int b = assign[cg->cells[1]];
            int big = a, small = b;
            if (small > big) { goto IF_T_00168; }
goto IF_E_00169;
IF_T_00168: {
 int t = big; big = small; small = t; 
}
IF_E_00169:

            return (small != 0 && big % small == 0 && big / small == tgt);
        
}
IF_E_00171:

        return 0;
    
}
IF_E_00173:


    if (op == '+') { goto IF_T_00183; }
goto IF_E_00184;
IF_T_00183: {

        int min = 0, max = 0;
        {
int i = 0;
F_LOOP_00174:
if (i < k) { goto F_BODY_00175; }
goto F_END_00177;
F_BODY_00175: {

            int cell = cg->cells[i];
            int v    = assign[cell];
            if (v) { goto IF_T_00180; }
goto IF_F_00182;
IF_T_00180: {

                min += v; max += v;
            
}
goto IF_E_00181;
IF_F_00182: {

                int m = domains[cell];
                if (!m) { goto IF_T_00178; }
goto IF_E_00179;
IF_T_00178: {
return 0;
}
IF_E_00179:

                min += mask_min(m);
                max += mask_max(m, P->N);
            
}
IF_E_00181:

        
}
F_STEP_00176:
i++;
goto F_LOOP_00174;
F_END_00177:
}

        return (min <= tgt && tgt <= max);
    
}
IF_E_00184:


    if (op == '*') { goto IF_T_00194; }
goto IF_E_00195;
IF_T_00194: {

        int minp = 1, maxp = 1;
        {
int i = 0;
F_LOOP_00185:
if (i < k) { goto F_BODY_00186; }
goto F_END_00188;
F_BODY_00186: {

            int cell = cg->cells[i];
            int v    = assign[cell];
            if (v) { goto IF_T_00191; }
goto IF_F_00193;
IF_T_00191: {

                minp *= v; maxp *= v;
            
}
goto IF_E_00192;
IF_F_00193: {

                int m = domains[cell];
                if (!m) { goto IF_T_00189; }
goto IF_E_00190;
IF_T_00189: {
return 0;
}
IF_E_00190:

                minp *= mask_min(m);
                maxp *= mask_max(m, P->N);
            
}
IF_E_00192:

        
}
F_STEP_00187:
i++;
goto F_LOOP_00185;
F_END_00188:
}

        return (minp <= tgt && tgt <= maxp);
    
}
IF_E_00195:


    if (op == '-' || op == '/') { goto IF_T_00218; }
goto IF_E_00219;
IF_T_00218: {

        if (k != 2) { goto IF_T_00196; }
goto IF_E_00197;
IF_T_00196: {
return 0;
}
IF_E_00197:

        int a = cg->cells[0];
        int b = cg->cells[1];
        int Am = assign[a] ? bit_of(assign[a]) : domains[a];
        int Bm = assign[b] ? bit_of(assign[b]) : domains[b];
        if (!Am || !Bm) { goto IF_T_00198; }
goto IF_E_00199;
IF_T_00198: {
return 0;
}
IF_E_00199:

        {
int va = 1;
F_LOOP_00200:
if (va <= P->N) { goto F_BODY_00201; }
goto F_END_00203;
F_BODY_00201: {
if (Am & bit_of(va)) { goto IF_T_00216; }
goto IF_E_00217;
IF_T_00216: {

            {
int vb = 1;
F_LOOP_00204:
if (vb <= P->N) { goto F_BODY_00205; }
goto F_END_00207;
F_BODY_00205: {
if (Bm & bit_of(vb)) { goto IF_T_00214; }
goto IF_E_00215;
IF_T_00214: {

                int big = va, small = vb;
                if (small > big) { goto IF_T_00208; }
goto IF_E_00209;
IF_T_00208: {
 int t = big; big = small; small = t; 
}
IF_E_00209:

                if (op == '-' && big - small == tgt) { goto IF_T_00210; }
goto IF_E_00211;
IF_T_00210: {
return 1;
}
IF_E_00211:

                if (op == '/' && small != 0 && big % small == 0 && big / small == tgt) { goto IF_T_00212; }
goto IF_E_00213;
IF_T_00212: {
return 1;
}
IF_E_00213:

            
}
IF_E_00215:

}
F_STEP_00206:
++vb;
goto F_LOOP_00204;
F_END_00207:
}

        
}
IF_E_00217:

}
F_STEP_00202:
++va;
goto F_LOOP_00200;
F_END_00203:
}

        return 0;
    
}
IF_E_00219:


    if (op == '=') { goto IF_T_00222; }
goto IF_E_00223;
IF_T_00222: {

        int cell = cg->cells[0];
        int v    = assign[cell];
        if (v) { goto IF_T_00220; }
goto IF_E_00221;
IF_T_00220: {
return v == tgt;
}
IF_E_00221:

        return mask_has(domains[cell], tgt) != 0;
    
}
IF_E_00223:


    return 1;
}

static int ineq_feasible(const Puzzle *P, const int *assign) {
    int N = P->N;
    int cells = N * N;
    {
int i = 0;
F_LOOP_00224:
if (i < P->ineq_count) { goto F_BODY_00225; }
goto F_END_00227;
F_BODY_00225: {

        int a = P->ineq[i].a;
        int b = P->ineq[i].b;
        char rel = P->ineq[i].rel;
        if (a < 0 || a >= cells || b < 0 || b >= cells) { goto IF_T_00228; }
goto IF_E_00229;
IF_T_00228: {

            
            goto F_STEP_00226;
        
}
IF_E_00229:

        int va = assign[a];
        int vb = assign[b];
        if (va == 0 || vb == 0) { goto IF_T_00230; }
goto IF_E_00231;
IF_T_00230: {
goto F_STEP_00226;
}
IF_E_00231:

        if (rel == '<' && !(va < vb)) { goto IF_T_00232; }
goto IF_E_00233;
IF_T_00232: {
return 0;
}
IF_E_00233:

        if (rel == '>' && !(va > vb)) { goto IF_T_00234; }
goto IF_E_00235;
IF_T_00234: {
return 0;
}
IF_E_00235:

    
}
F_STEP_00226:
i++;
goto F_LOOP_00224;
F_END_00227:
}

    return 1;
}




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

    {
int i = 0;
F_LOOP_00236:
if (i < cells) { goto F_BODY_00237; }
goto F_END_00239;
F_BODY_00237: {
if (S->assign[i] == 0) { goto IF_T_00258; }
goto IF_E_00259;
IF_T_00258: {

        int r = i / N;
        int c = i % N;
        int mask = S->domains[i];

        
        {
int v = 1;
F_LOOP_00240:
if (v <= N) { goto F_BODY_00241; }
goto F_END_00243;
F_BODY_00241: {

            if ((S->row_used[r] & bit_of(v)) || (S->col_used[c] & bit_of(v))) { goto IF_T_00244; }
goto IF_E_00245;
IF_T_00244: {
mask &= ~bit_of(v);
}
IF_E_00245:

        
}
F_STEP_00242:
++v;
goto F_LOOP_00240;
F_END_00243:
}

        if (mask == 0) { goto IF_T_00246; }
goto IF_E_00247;
IF_T_00246: {
return -2;
}
IF_E_00247:
 

        int k = 0;
        {
int v = 1;
F_LOOP_00248:
if (v <= N) { goto F_BODY_00249; }
goto F_END_00251;
F_BODY_00249: {
if (mask & bit_of(v)) { goto IF_T_00252; }
goto IF_E_00253;
IF_T_00252: {
k++;
}
IF_E_00253:

}
F_STEP_00250:
++v;
goto F_LOOP_00248;
F_END_00251:
}


        if (k < bestK) { goto IF_T_00256; }
goto IF_E_00257;
IF_T_00256: {

            bestK = k;
            best  = i;
            if (k == 1) { goto IF_T_00254; }
goto IF_E_00255;
IF_T_00254: {
goto F_END_00239;
}
IF_E_00255:

        
}
IF_E_00257:

    
}
IF_E_00259:

}
F_STEP_00238:
i++;
goto F_LOOP_00236;
F_END_00239:
}

    return best;
}

static void solver_dfs(Solver *S) {
    if (S->sol_count >= S->max_solutions) { goto IF_T_00260; }
goto IF_E_00261;
IF_T_00260: {
return;
}
IF_E_00261:


    int cell = solver_mrv_cell(S);
    if (cell == -2) { goto IF_T_00262; }
goto IF_E_00263;
IF_T_00262: {
return;
}
IF_E_00263:
      
    if (cell == -1) { goto IF_T_00264; }
goto IF_E_00265;
IF_T_00264: {
            
        S->sol_count++;
        return;
    
}
IF_E_00265:


    const int N = S->P->N;
    int r = cell / N;
    int c = cell % N;
    int mask = S->domains[cell];

    {
int v = 1;
F_LOOP_00266:
if (v <= N) { goto F_BODY_00267; }
goto F_END_00269;
F_BODY_00267: {

        if (!(mask & bit_of(v))) { goto IF_T_00270; }
goto IF_E_00271;
IF_T_00270: {
goto F_STEP_00268;
}
IF_E_00271:

        if ((S->row_used[r] & bit_of(v)) || (S->col_used[c] & bit_of(v))) { goto IF_T_00272; }
goto IF_E_00273;
IF_T_00272: {
goto F_STEP_00268;
}
IF_E_00273:


        S->assign[cell] = v;
        S->row_used[r] |= bit_of(v);
        S->col_used[c] |= bit_of(v);

        int ci = S->P->cell_to_cage[cell];
        if (cage_feasible_partial(S->P, ci, S->assign, S->domains) &&             ineq_feasible(S->P, S->assign)) { goto IF_T_00276; }
goto IF_E_00277;
IF_T_00276: {

            solver_dfs(S);
            if (S->sol_count >= S->max_solutions) { goto IF_T_00274; }
goto IF_E_00275;
IF_T_00274: {

                S->assign[cell] = 0;
                S->row_used[r] &= ~bit_of(v);
                S->col_used[c] &= ~bit_of(v);
                return;
            
}
IF_E_00275:

        
}
IF_E_00277:


        S->assign[cell] = 0;
        S->row_used[r] &= ~bit_of(v);
        S->col_used[c] &= ~bit_of(v);
    
}
F_STEP_00268:
++v;
goto F_LOOP_00266;
F_END_00269:
}

}

static int solve_count(const Puzzle *P, int max_solutions) {
    const int N     = P->N;
    const int cells = N * N;

    Solver S;
    S.P             = P;
    S.max_solutions = max_solutions;
    S.sol_count     = 0;

    {
int i = 0;
F_LOOP_00278:
if (i < cells) { goto F_BODY_00279; }
goto F_END_00281;
F_BODY_00279: {

        S.domains[i] = mask_full(N);
        int par = P->parity[i];
        if (par == 0) { goto IF_T_00296; }
goto IF_F_00298;
IF_T_00296: {

            int m = 0; {
int v = 1;
F_LOOP_00282:
if (v <= N) { goto F_BODY_00283; }
goto F_END_00285;
F_BODY_00283: {
if (v % 2 == 0) { goto IF_T_00286; }
goto IF_E_00287;
IF_T_00286: {
m |= bit_of(v);
}
IF_E_00287:

}
F_STEP_00284:
++v;
goto F_LOOP_00282;
F_END_00285:
}

            S.domains[i] &= m;
        
}
goto IF_E_00297;
IF_F_00298: {
if (par == 1) { goto IF_T_00294; }
goto IF_E_00295;
IF_T_00294: {

            int m = 0; {
int v = 1;
F_LOOP_00288:
if (v <= N) { goto F_BODY_00289; }
goto F_END_00291;
F_BODY_00289: {
if (v % 2 == 1) { goto IF_T_00292; }
goto IF_E_00293;
IF_T_00292: {
m |= bit_of(v);
}
IF_E_00293:

}
F_STEP_00290:
++v;
goto F_LOOP_00288;
F_END_00291:
}

            S.domains[i] &= m;
        
}
IF_E_00295:

}
IF_E_00297:

        if (S.domains[i] == 0) { goto IF_T_00299; }
goto IF_E_00300;
IF_T_00299: {
return 0;
}
IF_E_00300:

        S.assign[i] = 0;
    
}
F_STEP_00280:
i++;
goto F_LOOP_00278;
F_END_00281:
}

    {
int r = 0;
F_LOOP_00301:
if (r < N) { goto F_BODY_00302; }
goto F_END_00304;
F_BODY_00302: {
S.row_used[r] = 0;
}
F_STEP_00303:
r++;
goto F_LOOP_00301;
F_END_00304:
}

    {
int c = 0;
F_LOOP_00305:
if (c < N) { goto F_BODY_00306; }
goto F_END_00308;
F_BODY_00306: {
S.col_used[c] = 0;
}
F_STEP_00307:
c++;
goto F_LOOP_00305;
F_END_00308:
}


    solver_dfs(&S);
    return S.sol_count;
}




static int generate_unique(Puzzle *P) {
    const int N     = P->N;
    const int cells = N * N;

    int attempts = 0;
    
W_LOOP_00309:
if (attempts < 200) { goto W_BODY_00310; }
goto W_END_00311;
W_BODY_00310: {

        attempts++;

        
        gen_latin(N, P->Latin);

        
        int rem[CELLMAX];
        int rem_cnt = 0;
        {
int i = 0;
F_LOOP_00312:
if (i < cells) { goto F_BODY_00313; }
goto F_END_00315;
F_BODY_00313: {
rem[rem_cnt++] = i;
}
F_STEP_00314:
i++;
goto F_LOOP_00312;
F_END_00315:
}

        shuffle_int(rem, rem_cnt);
        gen_random_cages(N, rem, &rem_cnt, P->cages, &P->cage_count);

        
        {
int i = 0;
F_LOOP_00316:
if (i < cells) { goto F_BODY_00317; }
goto F_END_00319;
F_BODY_00317: {
P->cell_to_cage[i] = -1;
}
F_STEP_00318:
i++;
goto F_LOOP_00316;
F_END_00319:
}

        {
int ci = 0;
F_LOOP_00320:
if (ci < P->cage_count) { goto F_BODY_00321; }
goto F_END_00323;
F_BODY_00321: {

            {
int k = 0;
F_LOOP_00324:
if (k < P->cages[ci].cnt) { goto F_BODY_00325; }
goto F_END_00327;
F_BODY_00325: {

                P->cell_to_cage[ P->cages[ci].cells[k] ] = ci;
            
}
F_STEP_00326:
++k;
goto F_LOOP_00324;
F_END_00327:
}

        
}
F_STEP_00322:
++ci;
goto F_LOOP_00320;
F_END_00323:
}


        
        assign_ops_targets(N, P->Latin, P->cages, P->cage_count);

        
        generate_inequalities(P, 0.20);
        generate_parity(P,       0.18);

        
        int cnt = solve_count(P, 2);
        if (cnt == 1) { goto IF_T_00328; }
goto IF_E_00329;
IF_T_00328: {
return 1;
}
IF_E_00329:


        int tries_local = 0;
        int added = 0;
        
W_LOOP_00330:
if (cnt != 1 && tries_local < 16 && added < 8) { goto W_BODY_00331; }
goto W_END_00332;
W_BODY_00331: {

            tries_local++;
            int r = rnd_int(0, N - 1);
            int c = rnd_int(0, N - 1);

            
            int nbrs[4];
            int nk = neighbors4(N, r, c, nbrs);
            if (nk == 0) { goto IF_T_00333; }
goto IF_E_00334;
IF_T_00333: {
goto W_LOOP_00330;
}
IF_E_00334:

            int nb = nbrs[rnd_int(0, nk - 1)];
            int a  = idx_rc(r, c, N);
            int b  = nb;
            int va = P->Latin[a];
            int vb = P->Latin[b];
            if (va == vb) { goto IF_T_00335; }
goto IF_E_00336;
IF_T_00335: {
goto W_LOOP_00330;
}
IF_E_00336:


            if (P->ineq_count < INEQMAX) { goto IF_T_00337; }
goto IF_E_00338;
IF_T_00337: {

                Inequality q; q.a = a; q.b = b; q.rel = (va < vb ? '<' : '>');
                P->ineq[P->ineq_count++] = q;
                added++;
            
}
IF_E_00338:

            cnt = solve_count(P, 2);
        
}
goto W_LOOP_00330;
W_END_00332:

        if (cnt == 1) { goto IF_T_00339; }
goto IF_E_00340;
IF_T_00339: {
return 1;
}
IF_E_00340:

    
}
goto W_LOOP_00309;
W_END_00311:

    return 0;
}




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
    {
t = 0;
F_LOOP_00341:
if (t < 8) { goto F_BODY_00342; }
goto F_END_00344;
F_BODY_00342: {
s[t] = md->state[t];
}
F_STEP_00343:
t++;
goto F_LOOP_00341;
F_END_00344:
}

    {
t = 0;
F_LOOP_00345:
if (t < 16) { goto F_BODY_00346; }
goto F_END_00348;
F_BODY_00346: {

        W[t] = ((uint32_t)buf[t*4] << 24) |
               ((uint32_t)buf[t*4+1] << 16) |
               ((uint32_t)buf[t*4+2] << 8) |
               ((uint32_t)buf[t*4+3]);
    
}
F_STEP_00347:
t++;
goto F_LOOP_00345;
F_END_00348:
}

    {
t = 16;
F_LOOP_00349:
if (t < 64) { goto F_BODY_00350; }
goto F_END_00352;
F_BODY_00350: {
W[t] = Gamma1(W[t-2]) + W[t-7] + Gamma0(W[t-15]) + W[t-16];
}
F_STEP_00351:
t++;
goto F_LOOP_00349;
F_END_00352:
}

    {
t = 0;
F_LOOP_00353:
if (t < 64) { goto F_BODY_00354; }
goto F_END_00356;
F_BODY_00354: {

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
F_STEP_00355:
t++;
goto F_LOOP_00353;
F_END_00356:
}

    {
t = 0;
F_LOOP_00357:
if (t < 8) { goto F_BODY_00358; }
goto F_END_00360;
F_BODY_00358: {
md->state[t] += s[t];
}
F_STEP_00359:
t++;
goto F_LOOP_00357;
F_END_00360:
}

}

static void sha256_update(sha256_ctx *md, const uint8_t *in, size_t inlen) {
    
W_LOOP_00361:
if (inlen > 0) { goto W_BODY_00362; }
goto W_END_00363;
W_BODY_00362: {

        size_t n = 64 - md->curlen;
        if (n > inlen) { goto IF_T_00364; }
goto IF_E_00365;
IF_T_00364: {
n = inlen;
}
IF_E_00365:

        memcpy(md->buf + md->curlen, in, n);
        md->curlen += n;
        md->len    += n;
        in         += n;
        inlen      -= n;
        if (md->curlen == 64) { goto IF_T_00366; }
goto IF_E_00367;
IF_T_00366: {

            sha256_compress(md, md->buf);
            md->curlen = 0;
        
}
IF_E_00367:

    
}
goto W_LOOP_00361;
W_END_00363:

}

static void sha256_done(sha256_ctx *md, uint8_t *out) {
    uint64_t bitlen = md->len * 8;
    md->buf[md->curlen++] = 0x80;
    if (md->curlen > 56) { goto IF_T_00371; }
goto IF_E_00372;
IF_T_00371: {

        
W_LOOP_00368:
if (md->curlen < 64) { goto W_BODY_00369; }
goto W_END_00370;
W_BODY_00369: {
md->buf[md->curlen++] = 0;
}
goto W_LOOP_00368;
W_END_00370:

        sha256_compress(md, md->buf);
        md->curlen = 0;
    
}
IF_E_00372:

    
W_LOOP_00373:
if (md->curlen < 56) { goto W_BODY_00374; }
goto W_END_00375;
W_BODY_00374: {
md->buf[md->curlen++] = 0;
}
goto W_LOOP_00373;
W_END_00375:

    {
int i = 0;
F_LOOP_00376:
if (i < 8) { goto F_BODY_00377; }
goto F_END_00379;
F_BODY_00377: {
md->buf[56 + i] = (uint8_t)((bitlen >> (56 - 8 * i)) & 0xFF);
}
F_STEP_00378:
i++;
goto F_LOOP_00376;
F_END_00379:
}

    sha256_compress(md, md->buf);
    {
int i = 0;
F_LOOP_00380:
if (i < 8) { goto F_BODY_00381; }
goto F_END_00383;
F_BODY_00381: {

        out[i*4+0] = (md->state[i] >> 24) & 0xFF;
        out[i*4+1] = (md->state[i] >> 16) & 0xFF;
        out[i*4+2] = (md->state[i] >> 8) & 0xFF;
        out[i*4+3] = (md->state[i]) & 0xFF;
    
}
F_STEP_00382:
i++;
goto F_LOOP_00380;
F_END_00383:
}

}

static int sha256_file_hex(const char *path, char *hex_out ) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { goto IF_T_00384; }
goto IF_E_00385;
IF_T_00384: {
return -1;
}
IF_E_00385:


    sha256_ctx ctx;
    sha256_init(&ctx);

    uint8_t buf[4096];
    {
F_LOOP_00386:
if (1) { goto F_BODY_00387; }
goto F_END_00389;
F_BODY_00387: {

        size_t n = fread(buf, 1, sizeof(buf), fp);
        if (n > 0) { goto IF_T_00390; }
goto IF_E_00391;
IF_T_00390: {
sha256_update(&ctx, buf, n);
}
IF_E_00391:

        if (n < sizeof(buf)) { goto IF_T_00394; }
goto IF_E_00395;
IF_T_00394: {

            if (ferror(fp)) { goto IF_T_00392; }
goto IF_E_00393;
IF_T_00392: {
 fclose(fp); return -2; 
}
IF_E_00393:

            goto F_END_00389;
        
}
IF_E_00395:

    
}
F_STEP_00388:

goto F_LOOP_00386;
F_END_00389:
}

    fclose(fp);

    uint8_t digest[32];
    sha256_done(&ctx, digest);

    static const char *hx = "0123456789abcdef";
    {
int i = 0;
F_LOOP_00396:
if (i < 32) { goto F_BODY_00397; }
goto F_END_00399;
F_BODY_00397: {

        hex_out[i*2+0] = hx[digest[i] >> 4];
        hex_out[i*2+1] = hx[digest[i] & 0xF];
    
}
F_STEP_00398:
i++;
goto F_LOOP_00396;
F_END_00399:
}

    hex_out[64] = '\0';
    return 0;
}




static int generate_unique(Puzzle *P);  

static void build_puzzle(Puzzle *P, int N) {
    memset(P, 0, sizeof(*P));
    P->N = N;
    {
int i = 0;
F_LOOP_00400:
if (i < N * N) { goto F_BODY_00401; }
goto F_END_00403;
F_BODY_00401: {
P->parity[i] = -1;
}
F_STEP_00402:
i++;
goto F_LOOP_00400;
F_END_00403:
}

    
    rng_seed(FIXED_SEED);
    if (!generate_unique(P)) { goto IF_T_00404; }
goto IF_E_00405;
IF_T_00404: {

        exit(1);
    
}
IF_E_00405:

}




static int parse_canonical_grid_file(const char *path, int N, int *grid) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { goto IF_T_00406; }
goto IF_E_00407;
IF_T_00406: {

        return -1;
    
}
IF_E_00407:


    if (fseek(fp, 0, SEEK_END) != 0) { goto IF_T_00408; }
goto IF_E_00409;
IF_T_00408: {
 fclose(fp); return -1; 
}
IF_E_00409:

    long sz = ftell(fp);
    if (sz < 0) { goto IF_T_00410; }
goto IF_E_00411;
IF_T_00410: {
 fclose(fp); return -1; 
}
IF_E_00411:

    if (fseek(fp, 0, SEEK_SET) != 0) { goto IF_T_00412; }
goto IF_E_00413;
IF_T_00412: {
 fclose(fp); return -1; 
}
IF_E_00413:

 
    char *buf = (char*)malloc((size_t)sz + 1);
    if (!buf) { goto IF_T_00414; }
goto IF_E_00415;
IF_T_00414: {
 fclose(fp); return -1; 
}
IF_E_00415:

    size_t n = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    buf[n] = '\0';

    if (n == 0 || buf[n - 1] != '\n') { goto IF_T_00416; }
goto IF_E_00417;
IF_T_00416: {

        free(buf);
        return -1;
    
}
IF_E_00417:


    int    row = 0;
    size_t pos = 0;

    
W_LOOP_00418:
if (pos < n) { goto W_BODY_00419; }
goto W_END_00420;
W_BODY_00419: {

        size_t line_start = pos;
        size_t line_end   = line_start;
        
W_LOOP_00421:
if (line_end < n && buf[line_end] != '\n') { goto W_BODY_00422; }
goto W_END_00423;
W_BODY_00422: {
line_end++;
}
goto W_LOOP_00421;
W_END_00423:


        if (line_end == line_start) { goto IF_T_00424; }
goto IF_E_00425;
IF_T_00424: {

            free(buf);
            return -1;
        
}
IF_E_00425:


        int    col = 0;
        size_t i   = line_start;
        
W_LOOP_00426:
if (i < line_end) { goto W_BODY_00427; }
goto W_END_00428;
W_BODY_00427: {

            if (col >= N) { goto IF_T_00429; }
goto IF_E_00430;
IF_T_00429: {
 free(buf); return -1; 
}
IF_E_00430:

            if (i >= line_end || buf[i] < '0' || buf[i] > '9') { goto IF_T_00431; }
goto IF_E_00432;
IF_T_00431: {
 free(buf); return -1; 
}
IF_E_00432:


            int    v = 0;
            size_t j = i;
            
W_LOOP_00433:
if (j < line_end && buf[j] >= '0' && buf[j] <= '9') { goto W_BODY_00434; }
goto W_END_00435;
W_BODY_00434: {

                v = v * 10 + (buf[j] - '0');
                j++;
            
}
goto W_LOOP_00433;
W_END_00435:

            if (v < 1 || v > N) { goto IF_T_00436; }
goto IF_E_00437;
IF_T_00436: {
 free(buf); return -1; 
}
IF_E_00437:

            grid[row * N + col] = v;
            col++;

            if (j < line_end) { goto IF_T_00442; }
goto IF_F_00444;
IF_T_00442: {

                if (buf[j] != ' ') { goto IF_T_00438; }
goto IF_E_00439;
IF_T_00438: {
 free(buf); return -1; 
}
IF_E_00439:

                i = j + 1;
                if (i >= line_end || buf[i] < '0' || buf[i] > '9') { goto IF_T_00440; }
goto IF_E_00441;
IF_T_00440: {
 free(buf); return -1; 
}
IF_E_00441:

            
}
goto IF_E_00443;
IF_F_00444: {

                i = j; 
            
}
IF_E_00443:

        
}
goto W_LOOP_00426;
W_END_00428:


        if (col != N) { goto IF_T_00445; }
goto IF_E_00446;
IF_T_00445: {
 free(buf); return -1; 
}
IF_E_00446:

        if (line_end >= n || buf[line_end] != '\n') { goto IF_T_00447; }
goto IF_E_00448;
IF_T_00447: {
 free(buf); return -1; 
}
IF_E_00448:


        pos = line_end + 1;
        row++;
        if (row > N) { goto IF_T_00449; }
goto IF_E_00450;
IF_T_00449: {
 free(buf); return -1; 
}
IF_E_00450:

    
}
goto W_LOOP_00418;
W_END_00420:


    if (row != N) { goto IF_T_00451; }
goto IF_E_00452;
IF_T_00451: {
 free(buf); return -1; 
}
IF_E_00452:


    free(buf);
    return 0;
}




static int validate_grid(const Puzzle *P, const int *G) {
    int N = P->N;

    
    {
int r = 0;
F_LOOP_00453:
if (r < N) { goto F_BODY_00454; }
goto F_END_00456;
F_BODY_00454: {

        int seen = 0;
        {
int c = 0;
F_LOOP_00457:
if (c < N) { goto F_BODY_00458; }
goto F_END_00460;
F_BODY_00458: {

            int v = G[idx_rc(r, c, N)];
            if (v < 1 || v > N) { goto IF_T_00461; }
goto IF_E_00462;
IF_T_00461: {
return 0;
}
IF_E_00462:

            if (seen & bit_of(v)) { goto IF_T_00463; }
goto IF_E_00464;
IF_T_00463: {
return 0;
}
IF_E_00464:

            seen |= bit_of(v);
 
        
}
F_STEP_00459:
c++;
goto F_LOOP_00457;
F_END_00460:
}

    
}
F_STEP_00455:
r++;
goto F_LOOP_00453;
F_END_00456:
}


    
    {
int c = 0;
F_LOOP_00465:
if (c < N) { goto F_BODY_00466; }
goto F_END_00468;
F_BODY_00466: {

        int seen = 0;
        {
int r = 0;
F_LOOP_00469:
if (r < N) { goto F_BODY_00470; }
goto F_END_00472;
F_BODY_00470: {

            int v = G[idx_rc(r, c, N)];
            if (seen & bit_of(v)) { goto IF_T_00473; }
goto IF_E_00474;
IF_T_00473: {
return 0;
}
IF_E_00474:

            seen |= bit_of(v);
  
        
}
F_STEP_00471:
r++;
goto F_LOOP_00469;
F_END_00472:
}

    
}
F_STEP_00467:
c++;
goto F_LOOP_00465;
F_END_00468:
}


    
    {
int i = 0;
F_LOOP_00475:
if (i < N * N) { goto F_BODY_00476; }
goto F_END_00478;
F_BODY_00476: {

        if (P->parity[i] == 0 && (G[i] % 2) != 0) { goto IF_T_00479; }
goto IF_E_00480;
IF_T_00479: {
return 0;
}
IF_E_00480:

        if (P->parity[i] == 1 && (G[i] % 2) != 1) { goto IF_T_00481; }
goto IF_E_00482;
IF_T_00481: {
return 0;
}
IF_E_00482:


    
}
F_STEP_00477:
i++;
goto F_LOOP_00475;
F_END_00478:
}


    
    {
        int cells = N * N;
        {
int i = 0;
F_LOOP_00483:
if (i < P->ineq_count) { goto F_BODY_00484; }
goto F_END_00486;
F_BODY_00484: {

            int a = P->ineq[i].a;
            int b = P->ineq[i].b;
            char rel = P->ineq[i].rel;
            if (a < 0 || a >= cells || b < 0 || b >= cells) { goto IF_T_00487; }
goto IF_E_00488;
IF_T_00487: {
goto F_STEP_00485;
}
IF_E_00488:
 
            int va = G[a];
            int vb = G[b];
            if (rel == '<' && !(va < vb)) { goto IF_T_00489; }
goto IF_E_00490;
IF_T_00489: {
return 0;
}
IF_E_00490:

            if (rel == '>' && !(va > vb)) { goto IF_T_00491; }
goto IF_E_00492;
IF_T_00491: {
return 0;
}
IF_E_00492:

 
        
}
F_STEP_00485:
i++;
goto F_LOOP_00483;
F_END_00486:
}

    }

    
    {
int ci = 0;
F_LOOP_00493:
if (ci < P->cage_count) { goto F_BODY_00494; }
goto F_END_00496;
F_BODY_00494: {

        const Cage *cg = &P->cages[ci];
        char op = cg->op;
        int  tgt = cg->target;
        if (op == '=') { goto IF_T_00531; }
goto IF_F_00533;
IF_T_00531: {

            if (G[cg->cells[0]] != tgt) { goto IF_T_00497; }
goto IF_E_00498;
IF_T_00497: {
return 0;
}
IF_E_00498:

        
}
goto IF_E_00532;
IF_F_00533: {
if (op == '+') { goto IF_T_00528; }
goto IF_F_00530;
IF_T_00528: {

            int s = 0; {
int k = 0;
F_LOOP_00499:
if (k < cg->cnt) { goto F_BODY_00500; }
goto F_END_00502;
F_BODY_00500: {
s += G[cg->cells[k]];
}
F_STEP_00501:
k++;
goto F_LOOP_00499;
F_END_00502:
}

            if (s != tgt) { goto IF_T_00503; }
goto IF_E_00504;
IF_T_00503: {
return 0;
}
IF_E_00504:

        
}
goto IF_E_00529;
IF_F_00530: {
if (op == '*') { goto IF_T_00525; }
goto IF_F_00527;
IF_T_00525: {

            int p = 1; {
int k = 0;
F_LOOP_00505:
if (k < cg->cnt) { goto F_BODY_00506; }
goto F_END_00508;
F_BODY_00506: {
p *= G[cg->cells[k]];
}
F_STEP_00507:
k++;
goto F_LOOP_00505;
F_END_00508:
}

            if (p != tgt) { goto IF_T_00509; }
goto IF_E_00510;
IF_T_00509: {
return 0;
}
IF_E_00510:

        
}
goto IF_E_00526;
IF_F_00527: {
if (op == '-') { goto IF_T_00522; }
goto IF_F_00524;
IF_T_00522: {

            int a = G[cg->cells[0]];
            int b = G[cg->cells[1]];
            int big = a, small = b;
            if (small > big) { goto IF_T_00511; }
goto IF_E_00512;
IF_T_00511: {
 int t = big; big = small; small = t; 
}
IF_E_00512:

            if (big - small != tgt) { goto IF_T_00513; }
goto IF_E_00514;
IF_T_00513: {
return 0;
}
IF_E_00514:

        
}
goto IF_E_00523;
IF_F_00524: {
if (op == '/') { goto IF_T_00519; }
goto IF_F_00521;
IF_T_00519: {

            int a = G[cg->cells[0]];
            int b = G[cg->cells[1]];
            int big = a, small = b;
            if (small > big) { goto IF_T_00515; }
goto IF_E_00516;
IF_T_00515: {
 int t = big; big = small; small = t; 
}
IF_E_00516:

            if (!(small != 0 && big % small == 0 && big / small == tgt)) { goto IF_T_00517; }
goto IF_E_00518;
IF_T_00517: {
return 0;
}
IF_E_00518:

        
}
goto IF_E_00520;
IF_F_00521: {

            return 0;
        
}
IF_E_00520:

}
IF_E_00523:

}
IF_E_00526:

}
IF_E_00529:

}
IF_E_00532:


    
}
F_STEP_00495:
++ci;
goto F_LOOP_00493;
F_END_00496:
}


    return 1;
}




int main(int argc, char **argv) {
    Puzzle P;
    build_puzzle(&P, NDEFAULT);

    if (argc == 2) { goto IF_T_00540; }
goto IF_E_00541;
IF_T_00540: {

        
        const char *path = argv[1];
        int G[CELLMAX];

        if (parse_canonical_grid_file(path, P.N, G) != 0) { goto IF_T_00534; }
goto IF_E_00535;
IF_T_00534: {

            return 2; 
        
}
IF_E_00535:

        if (!validate_grid(&P, G)) { goto IF_T_00536; }
goto IF_E_00537;
IF_T_00536: {

            return 3;
        
}
IF_E_00537:

        char hex[65];
        int rc = sha256_file_hex(path, hex);
        if (rc != 0) { goto IF_T_00538; }
goto IF_E_00539;
IF_T_00538: {

            return 4;
        
}
IF_E_00539:

        printf("CyKor{%s}\n", hex);
        return 0;
    
}
IF_E_00541:

}