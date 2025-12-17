#!/usr/bin/env python3
import argparse, os, random, re, shlex, subprocess, sys

READelf = os.environ.get("READELF", "readelf")

def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"cmd failed: {' '.join(cmd)}\nSTDERR:\n{p.stderr}")
    return p.stdout

def parse_text_section(bin_path):
    # readelf -WS 출력에서 .text 섹션의 VMA/크기 파싱
    out = run([READelf, "-WS", bin_path])
    # 줄 예시:
    # [Nr] Name   Type  Address          Off    Size ...
    # [13] .text  PROGBITS 0000000000401000  001000 00092a ...
    rex = re.compile(r"\[\s*\d+\]\s+\.text\s+\S+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)")
    for line in out.splitlines():
        m = rex.search(line)
        if m:
            addr = int(m.group(1), 16)  # VMA (정보용)
            off  = int(m.group(2), 16)  # 파일 오프셋 (여기선 사용 X)
            size = int(m.group(3), 16)  # 섹션 크기
            return addr, size
    raise RuntimeError(".text section not found (readelf parse failed)")

# 헷갈리는 ASCII로만 구성 (툴 호환성↑, 시각 혼동↑)
HOMO_BLOCKS = [
    "lIlI", "llII", "IlIl", "lI1I", "I1lI", "l11I", "IIll", "lIIl",
    "O0O", "0OO", "OO0", "0O0", "O00", "00O"
]

def gen_confusing_name(seqno, off):
    base = random.choice(HOMO_BLOCKS)
    # 길이를 6~12 사이에서 랜덤하게
    extra = "".join(random.choice("lI1O0") for _ in range(random.randint(2, 8)))
    return f"{base}{extra}_{seqno:04d}_at_{off:06x}"

def chunked(iterable, max_items):
    buf = []
    for x in iterable:
        buf.append(x)
        if len(buf) >= max_items:
            yield buf
            buf = []
    if buf:
        yield buf

def main():
    ap = argparse.ArgumentParser(description="Sprinkle fake function symbols into .text using objcopy --add-symbol")
    ap.add_argument("input", help="input ELF")
    ap.add_argument("output", help="output ELF")
    ap.add_argument("--objcopy", default=os.environ.get("OBJCOPY","objcopy"),
                    help="objcopy or llvm-objcopy (default: objcopy)")
    ap.add_argument("--min-step", default="0x50", help="min step in bytes (hex or dec)")
    ap.add_argument("--max-step", default="0x100", help="max step in bytes (hex or dec)")
    ap.add_argument("--seed", default=None, help="random seed (hex or dec)")
    ap.add_argument("--max-count", type=int, default=0, help="hard cap on number of symbols (0=unlimited)")
    ap.add_argument("--batch-size", type=int, default=2000, help="how many --add-symbol per objcopy call")
    args = ap.parse_args()

    min_step = int(args.min_step, 0)
    max_step = int(args.max_step, 0)
    if min_step <= 0 or max_step < min_step:
        raise SystemExit("invalid step range")

    if args.seed is not None:
        random.seed(int(args.seed, 0))

    # 출력 파일은 입력 파일을 먼저 복사
    if os.path.abspath(args.input) != os.path.abspath(args.output):
        # cp 보다는 파이썬으로 복사
        with open(args.input, "rb") as fsrc, open(args.output, "wb") as fdst:
            fdst.write(fsrc.read())

    vma, text_size = parse_text_section(args.output)  # 출력(작업 대상)에서 파싱
    # .text 내부 오프셋 기준으로 심볼 위치 선정
    offsets = []
    off = 0
    seq = 0
    while off < text_size:
        step = random.randint(min_step, max_step)
        off += step
        if off >= text_size:
            break
        offsets.append(off)
        seq += 1
        if args.max_count and seq >= args.max_count:
            break

    # 심볼명 생성 (중복 회피)
    used = set()
    syms = []
    for i, off in enumerate(offsets, 1):
        name = gen_confusing_name(i, off)
        while name in used:
            name = gen_confusing_name(i, off)
        used.add(name)
        # --add-symbol NAME=.text:0xOFF,function,local
        syms.append((name, off))

    if not syms:
        print("No symbols to add (range too small?).")
        return

    print(f".text size: 0x{text_size:x}  | symbols to add: {len(syms)}")

    # 너무 많은 인자를 피하려고 배치로 objcopy 여러 번 실행
    for batch in chunked(syms, args.batch_size):
        cmd = [args.objcopy]
        for (name, off) in batch:
            spec = f"{name}=.text:0x{off:x},function,local"
            cmd += ["--add-symbol", spec]
        cmd += [args.output, args.output]  # in-place 업데이트
        # 실행
        # print("RUN:", " ".join(shlex.quote(c) for c in cmd))
        run(cmd)

    print("Done. Wrote:", args.output)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("ERROR:", e, file=sys.stderr)
        sys.exit(1)
