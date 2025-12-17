from typing import List, Optional
import random
from z3 import BitVec, BitVecVal, Solver, ForAll, Distinct, sat

MASK = (1<<64)-1
U64  = lambda x: BitVecVal(x & MASK, 64)
u64c = lambda x: f"UINT64_C({x & MASK})"

def OPQ_name(mode:str)->str:
    return "OPQ" if mode=="volatile" else ("OPQ_ASM" if mode=="asm" else "OPQ")

# ==== non-trivial 0 gadgets ====
def Z_add_decomp(x, y, vx, vy):
    # (x ^ y) + 2*(x & y) - (x + y) == 0
    z = (vx ^ vy) + ((vx & vy) << 1) - (vx + vy)
    c = f"((({x}) ^ ({y})) + ((({x}) & ({y})) << 1) - (({x}) + ({y})))"
    return z, c

def Z_or_and(x, y, vx, vy):
    # (x | y) + (x & y) - (x + y) == 0
    z = (vx | vy) + (vx & vy) - (vx + vy)
    c = f"((({x}) | ({y})) + (({x}) & ({y})) - (({x}) + ({y})))"
    return z, c

def Z_partition(x, y, vx, vy):
    # (x & y) + (x & ~y) - x == 0
    z = (vx & vy) + (vx & (~vy)) - vx
    c = f"((({x}) & ({y})) + (({x}) & ~({y})) - ({x}))"
    return z, c

def Z_mix3(a,b,c, va,vb,vc):
    # (a ^ (b ^ c)) - ((a ^ b) ^ c) == 0
    z = (va ^ (vb ^ vc)) - ((va ^ vb) ^ vc)
    s = f"((({a}) ^ (({b}) ^ ({c}))) - ((({a}) ^ ({b})) ^ ({c})))"
    return z, s

def allones_str(vs, opq="OPQ"):
    if not vs: return "~(0)"
    xs = [f"(({opq}(&{v})) ^ ({opq}(&{v})))" for v in vs]
    return f"~({' | '.join(xs)})"

def mask_is_zero_str(vname: str, opq="OPQ") -> str:
    # nz_bit = ((u | -u) >> 63)  // u!=0 -> 1, u==0 -> 0
    # zero_mask = (~0) * (1 - nz_bit)   // u==0 -> ~0, u!=0 -> 0
    u = f"{opq}(&{vname})"
    allones = "~(UINT64_C(0))"
    nz_bit = f"((((uint64_t)({u})) | ((uint64_t)(UINT64_C(0) - ({u})))) >> 63)"
    return f"(({allones}) * (UINT64_C(1) - ({nz_bit})))"

def mask_is_nonzero_str(vname: str, opq="OPQ") -> str:
    # nonzero_mask = (~0) * nz_bit    // u!=0 -> ~0, u==0 -> 0
    u = f"{opq}(&{vname})"
    allones = "~(UINT64_C(0))"
    nz_bit = f"((((uint64_t)({u})) | ((uint64_t)(UINT64_C(0) - ({u})))) >> 63)"
    return f"(({allones}) * ({nz_bit}))"

# === 64-bit MBA Expression Generator ===
def gen_mba(inp: List[Optional[int]], out: int,
            n_const_terms=3, n_zero_terms=6, seed=None,
            opaque_mode="volatile",  # "volatile" | "asm"
            distinct_const_coeffs=True) -> str:
    """
    EXAMPLE USAGE:
        expr = gen_mba(
            inp=[None, 0x1234, None],
            out=0xDEADBEEFCAFEBABE,
            n_const_terms=4, n_zero_terms=8,
            seed=20250903,
            opaque_mode="volatile"
        )
    """
    rng = random.Random(seed)
    n = len(inp)
    v_z3 = [BitVec(f"v{i}", 64) for i in range(n)]
    v_id = [f"v{i}" for i in range(n)]
    opq  = OPQ_name(opaque_mode)

    A_str = allones_str(v_id, opq=opq)

    ks = [BitVec(f"k{j}", 64) for j in range(max(1,n_const_terms))]
    const_terms_z3 = ks
    const_terms_c  = [f"(({A_str}) & K{j})" for j in range(len(ks))]

    z_terms_z3, z_terms_c, alphas = [], [], []
    zero_builders2 = [Z_add_decomp, Z_or_and, Z_partition]
    for _ in range(max(0, n_zero_terms)):
        kind = rng.choice([2,3]) if n>=3 else 2
        if kind==3:
            i,j,k = rng.randrange(n), rng.randrange(n), rng.randrange(n)
            z3t, cs = Z_mix3(f"{opq}(&{v_id[i]})", f"{opq}(&{v_id[j]})", f"{opq}(&{v_id[k]})",
                             v_z3[i], v_z3[j], v_z3[k])
        else:
            i,j = rng.randrange(n or 1), rng.randrange(n or 1)
            z3t, cs = rng.choice(zero_builders2)(
                f"{opq}(&{v_id[i]})", f"{opq}(&{v_id[j]})", v_z3[i], v_z3[j]
            )
        z_terms_z3.append(z3t)
        z_terms_c.append(cs)
        alphas.append(BitVec(f"a{len(alphas)}", 64))

    s = Solver()

    for i,val in enumerate(inp):
        if val is not None:
            s.add(v_z3[i] == U64(val))

    for k in ks: s.add(k != U64(0))
    for a in alphas: s.add(a != U64(0))
    if distinct_const_coeffs and len(ks) > 1:
        s.add(Distinct(*ks))

    E_z3 = BitVec("E", 64)
    sumk = U64(0)
    for k in const_terms_z3: sumk = sumk + k
    s.add(E_z3 == sumk)

    free = [v_z3[i] for i,val in enumerate(inp) if val is None]
    out_bv = U64(out)
    if free:
        s.add(ForAll(free, E_z3 == out_bv))
    else:
        s.add(E_z3 == out_bv)

    assert s.check() == sat
    m = s.model()
    k_vals = [m.evaluate(k).as_long() & MASK for k in ks]
    a_vals = [m.evaluate(a).as_long() & MASK for a in alphas]

    pieces = []
    for j, term in enumerate(const_terms_c):
        pieces.append(f"({term.replace(f'K{j}', u64c(k_vals[j]))})")
    for i, term in enumerate(z_terms_c):
        pieces.append(f"(({u64c(a_vals[i])}) * ({term}))")
    rng.shuffle(pieces)
    return " + ".join(pieces) if pieces else u64c(out)

def obf_cond_mask(vname: str, opq: str = "OPQ") -> str:
    u = f"{opq}(&{vname})"
    nz = f"((((uint64_t)({u})) | ((uint64_t)(UINT64_C(0) - ({u})))) >> 63)"   # 0 or 1
    # 여기에 0 gadget 하나 씌우기
    zg = f"((({u}) ^ ({u})) + ((({u}) & ({u})) << 1) - (({u}) + ({u})))"      # == 0
    # 보기만 지저분하게
    return f"(({nz}) ^ (({zg}) & UINT64_C(0)))"


def gen_mba_cond(inp,                # List[Optional[int]]
                 out_zero,           # vi==0일 때 결과 상수
                 out_nonzero,        # vi!=0일 때 결과 상수
                 gate_idx=0,         # 어떤 입력 vi를 게이트로 쓸지
                 pick_when="zero",   # "zero"이면 A가 vi==0일 때, "nonzero" 반대
                 seedA=1234, seedB=5678,
                 **kwargs) -> str:
    """
    RESULT = (MASK & A) | (~MASK & B)
    A = gen_mba(..., out=out_zero or out_nonzero)
    B = gen_mba(..., out=the other)
    """
    opq = OPQ_name(kwargs.get("opaque_mode", "volatile"))
    vname = f"v{gate_idx}"

    # A/B 매핑: cond_bit==1 일 때 A가 나오도록 배치
    if pick_when == "nonzero":
        # v != 0  -> out_nonzero (A)
        # v == 0  -> out_zero    (B)
        A = gen_mba(inp=inp, out=out_nonzero, seed=seedA, **kwargs)
        B = gen_mba(inp=inp, out=out_zero,    seed=seedB, **kwargs)
        invert = False
    else:
        # v == 0  -> out_zero    (A)
        # v != 0  -> out_nonzero (B)
        A = gen_mba(inp=inp, out=out_zero,    seed=seedA, **kwargs)
        B = gen_mba(inp=inp, out=out_nonzero, seed=seedB, **kwargs)
        invert = True

    # cond_bit: 0/1 (OPQ는 *a1 반환이므로 포인터 전달이 맞음)
    u = f"{opq}(&{vname})"
    nz_bit = f"((((uint64_t)({u})) | ((uint64_t)(UINT64_C(0) - ({u})))) >> 63)"  # v!=0 -> 1, v==0 -> 0

    # 살짝 감추기 위한 0-gadget (항등 0) — 같은 vname 사용
    zg = f"((({u}) ^ ({u})) + ((({u}) & ({u})) << 1) - (({u}) + ({u})))"

    # 최종 cond_bit (0/1). pick_when=="zero"면 반전.
    cond_bit_raw = f"(({nz_bit}) ^ (({zg}) & UINT64_C(0)))"
    cond_bit = f"(UINT64_C(1) - ({cond_bit_raw}))" if invert else cond_bit_raw

    # 0/1 -> 0/~0 마스크로 확장 (unsigned underflow)
    mask = f"(UINT64_C(0) - ({cond_bit}))"

    # MUX: 전체 64비트 선택
    # mid = A ^ B  # (원하면 이 형태로도 가능: B ^ (mask & (A ^ B)))
    expr = f"((({mask}) & ({A})) | ((~({mask})) & ({B})))"
    return expr