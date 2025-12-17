import random
from typing import List, Tuple
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

REGS = ["rax","rcx","rdx","rbx","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"]

# "패턴" 템플릿들: {r}, {imm}, {local} 같은 placeholder 채워서 사용
PATTERN_TEMPLATES = [
    # 레지스터 연산
    "mov {r}, {imm32}",
    "mov {r}, {r2}",
    "xor {r}, {r}",
    "add {r}, {imm8}",
    "add {r}, {imm32}",
    "sub {r}, {imm8}",
    "sub {r}, {imm32}",
    "and {r}, {imm8}",
    "and {r}, {imm32}",
    "or {r}, {imm8}",
    "or {r}, {imm32}",
    "xor {r}, {imm8}",
    "xor {r}, {imm32}",
    "inc {r}",
    "dec {r}",
    "shl {r}, {imm8}",
    "shr {r}, {imm8}",
    "rol {r}, {imm8}",
    "ror {r}, {imm8}",

    # 주소 계산 / 배열 인덱싱처럼 보이게
    "lea {r}, [{r2} + {disp_choice}]",

    # rbp 기반 로컬 변수처럼 보이는 접근
    "mov {r}, [rbp{local8}]",
    "mov [rbp{local8}], {r}",
    "add {r}, [rbp{local8}]",
    "sub [rbp{local8}], {r}",
    "xor {r}, [rbp{local8}]",
    "xor [rbp{local8}], {r}",
    "cmp {r}, [rbp{local8}]",
    "cmp [rbp{local8}], {r}",
    "test {r}, [rbp{local8}]",

    # rsp 기반 스택 변수처럼 보이는 접근
    "mov {r}, [rsp{local8}]",
    "mov [rsp{local8}], {r}",
    "add {r}, [rsp{local8}]",
    "sub [rsp{local8}], {r}",
    "xor {r}, [rsp{local8}]",
    "xor [rsp{local8}], {r}",
    "cmp {r}, [rsp{local8}]",
    "cmp [rsp{local8}], {r}",
    "test {r}, [rsp{local8}]",

    # 더 큰 오프셋 (disp32 나올 수 있게)
    "lea {r}, [rbp{local32}]",
    "lea {r}, [rsp{local32}]",

    # 비교 / test / call (실행되면 터져도 상관 없음)
    "cmp {r}, {imm32}",
    "cmp {r}, {imm8}",
    "test {r}, {imm32}",
    "call {r}",         # call rax 처럼 보이는 간접 호출
]

# push/pop/leave/ret 는 전부 제거
# 필요하면 prologue 느낌만 내고 싶을 때 쓸 수 있는 애들만 남김
FIXED_TEMPLATES = [
    "mov rbp, rsp",
    "sub rsp, 0x20",
    "add rsp, 0x20",
]

def pick_reg(exclude: List[str]=None) -> str:
    pool = [r for r in REGS if not exclude or r not in exclude]
    return random.choice(pool)

def rand_imm8() -> int:
    return random.randint(-128, 127)

def rand_imm32() -> int:
    return random.randint(-2**31, 2**31-1)

def rand_disp_choice() -> str:
    # disp8 / disp32 섞어서 길이 다양화
    if random.random() < 0.6:
        return str(rand_imm8())
    else:
        return str(rand_imm32())

def rand_local8() -> str:
    # [rbp-0x10], [rbp-0x20] 같은 음수 오프셋 위주
    return str(random.randint(-0x80, -0x8))

def rand_local32() -> str:
    # 좀 더 큰 로컬/스택 오프셋
    return str(random.randint(-0x1000, -0x10))

def instantiate_pattern_template(tmpl: str) -> str:
    r  = pick_reg()
    r2 = pick_reg(exclude=[r])
    s = tmpl
    s = s.replace("{r}", r)
    s = s.replace("{r2}", r2)

    if "{imm8}" in s:
        s = s.replace("{imm8}", str(rand_imm8()))
    if "{imm32}" in s:
        s = s.replace("{imm32}", str(rand_imm32()))
    if "{disp_choice}" in s:
        s = s.replace("{disp_choice}", rand_disp_choice())
    if "{local8}" in s:
        s = s.replace("{local8}", rand_local8())
    if "{local32}" in s:
        s = s.replace("{local32}", rand_local32())

    # [ rbp-16 ] 같은 거 정리
    s = s.replace("[ ", "[").replace(" ]", "]")
    return s

def assemble(asm_lines: List[str]) -> bytes:
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    code = "\n".join(asm_lines)
    try:
        encoding, _ = ks.asm(code)
    except Exception as e:
        raise RuntimeError(f"Keystone assemble error: {e}\n---\n{code}")
    return bytes(encoding)

def disasm_all(b: bytes) -> List[str]:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    out = []
    for insn in md.disasm(b, 0x1000):
        out.append(f"{insn.mnemonic} {insn.op_str}".strip())
    return out

def build_candidate_pool(pool_size: int = 300, max_trials: int = 3000):
    """
    개별 인스트럭션 후보들을 미리 생성해서 (asm, bytes) 리스트로 반환.
    여기 있는 byte 길이들만 이용해서 나중에 N을 정확히 쪼갬.
    """
    candidates: List[Tuple[str, bytes]] = []
    trials = 0

    all_templates = PATTERN_TEMPLATES + FIXED_TEMPLATES

    while len(candidates) < pool_size and trials < max_trials:
        trials += 1
        tmpl = random.choice(all_templates)

        # placeholder 포함/미포함 분기
        if "{" in tmpl:
            asm = instantiate_pattern_template(tmpl)
        else:
            asm = tmpl

        try:
            b_inst = assemble([asm])
        except Exception:
            continue

        # 혹시라도 nop 생기면 버리기 (안 쓰고 싶다면)
        dis = disasm_all(b_inst)
        if dis and dis[0].startswith("nop"):
            continue

        candidates.append((asm, b_inst))

    if not candidates:
        raise RuntimeError("No instruction candidates could be generated")

    return candidates

def pick_sequence_by_length(candidates: List[Tuple[str, bytes]], target_len: int) -> List[int]:
    """
    candidates에서 byte 길이들의 합이 target_len이 되도록
    인덱스들의 시퀀스를 찾는다. 없으면 RuntimeError.
    """
    lengths = [len(b) for (_, b) in candidates]
    memo = {}

    def dfs(rem: int) -> List[int] | None:
        if rem == 0:
            return []
        if rem < 0:
            return None
        if rem in memo:
            return memo[rem]

        indices = list(range(len(candidates)))
        random.shuffle(indices)

        for i in indices:
            L = lengths[i]
            if L > rem:
                continue
            sub = dfs(rem - L)
            if sub is not None:
                memo[rem] = [i] + sub
                return memo[rem]

        memo[rem] = None
        return None

    seq = dfs(target_len)
    if seq is None:
        raise RuntimeError(f"Cannot compose {target_len} bytes from candidate instruction lengths")
    return seq

def generate_random_x64_block(byte_len: int, seed: int=None) -> Tuple[str, bytes]:
    """
    byte_len 바이트 정확히 맞춰서 x64 명령열 생성.
    - NOP 패딩 X
    - 전부 "유의미해 보이는" 인스트럭션들로 구성
    - unreachable 코드용이라 실제 실행 시 크래시 나도 상관 없음
    """
    if seed is not None:
        random.seed(seed)

    candidates = build_candidate_pool()
    seq_indices = pick_sequence_by_length(candidates, byte_len)

    asm_lines = [candidates[i][0] for i in seq_indices]
    blob = b"".join(candidates[i][1] for i in seq_indices)

    # sanity check
    if len(blob) != byte_len:
        raise RuntimeError(f"length mismatch: got {len(blob)} vs target {byte_len}")

    asm_text = "\n".join(asm_lines)
    return asm_text, blob

if __name__ == "__main__":
    N = 24
    asm, blob = generate_random_x64_block(N, seed=0xC0FFEE)
    print(f"; generated {len(blob)} bytes")
    print(asm)
    print("hex:", blob.hex())
    print(blob)
