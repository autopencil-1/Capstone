import re
import multiprocessing
from typing import Tuple, List

# 멀티프로세싱 워커에서 실행될 전역 함수 (Pickle 가능해야 함)
def _worker_process_chunk(args):
    """
    개별 청크(함수 본문 등)를 처리하는 워커 함수.
    chunk_id를 받아 라벨의 유니크함을 보장함.
    """
    text, chunk_id = args
    if not text.strip():
        return text

    # 워커 내에서 독립적인 Preprocesser 인스턴스 생성
    # 라벨 충돌 방지를 위해 chunk_id를 prefix로 사용
    proc = Preprocesser(content=text, chunk_id=chunk_id)
    return proc.preprocess_segment()

class Preprocesser:
    def __init__(self, content=None, file_path=None, out_path=None, chunk_id=0):
        if content is not None:
            self.content = content
        elif file_path:
            with open(file_path, "r", encoding="utf-8") as f:
                self.content = f.read()
        else:
            self.content = ""
            # 워커로 호출될 때는 content가 필수지만, 초기화 에러 방지용

        self.out_path = out_path
        self.result = ""
        self._chunk_id = chunk_id
        self._label_counter = 0
        self.INDENT = self._detect_indent_unit(self.content)

    # ===== Public API =====
    def get(self):
        return self.result

    def preprocess(self):
        """
        메인 진입점: 코드를 Top-level 단위로 쪼개서 병렬 처리
        """
        # 1. 주석 제거 (전체적으로 한 번 수행)
        clean_content = self._strip_comments_and_preserve_strings(self.content)

        # 2. Top-level 단위(함수, 전역변수, 구조체 등)로 분할
        chunks = self._split_top_level_chunks(clean_content)

        # 3. Multiprocessing Pool을 이용해 병렬 처리
        # 작업량이 있는 청크(함수 본문)만 처리하고, 단순 선언부는 가볍게 처리
        tasks = []
        for idx, chunk in enumerate(chunks):
            tasks.append((chunk, idx))

        # CPU 코어 수만큼 프로세스 생성
        cpu_count = multiprocessing.cpu_count()
        with multiprocessing.Pool(processes=cpu_count) as pool:
            processed_chunks = pool.map(_worker_process_chunk, tasks)

        # 4. 결과 병합
        self.result = "".join(processed_chunks)
        
        # 5. 최종 들여쓰기 정리 (선택 사항, 병합 후 전체 밸런스 맞춤)
        # self.result = self._reindent_whole_code(self.result, label_column0=True)
        
        return self

    def preprocess_segment(self):
        """
        워커 내부에서 실제 변환 로직을 수행하는 함수 (재귀적용)
        """
        s = self.content
        
        # 1) 단문 if 중괄호 처리
        s = self._ensure_braced_single_line_ifs(s)
        s = self._compact_simple_braced_ifs(s)

        # 2) 재귀적 변환 (Loop, If-Else, Flattening을 한 번의 패스로 처리 시도)
        # 안정성을 위해 최대 반복 횟수를 두지만, 
        # 내부 로직이 재귀적이므로 대부분 1-2 pass 안에 끝남.
        max_iterations = 20
        for i in range(max_iterations):
            print(f"[Chunk {self._chunk_id}] Transform pass {i+1}")
            original_s = s
            s = self._transform_recursive(s)
            if s == original_s:
                break
        
        # 3) 들여쓰기 정리 (청크 단위)
        s = self._reindent_whole_code(s, label_column0=True)
        return s

    def build(self):
        if not self.out_path:
            raise RuntimeError("output file must be provided")
        with open(self.out_path, "w", encoding="utf-8") as f:
            f.write(self.result)

    # ===== Utilities =====
    def _gen_label(self, base: str) -> str:
        self._label_counter += 1
        # 청크 ID를 포함하여 병렬 처리 시에도 유니크함 보장
        return f"{base}_{self._chunk_id}_{self._label_counter:04d}"

    def _detect_indent_unit(self, s: str) -> str:
        for ln in s.splitlines():
            i = 0
            while i < len(ln) and ln[i] in (" ", "\t"):
                i += 1
            if i > 0 and "\t" in ln[:i]:
                return "\t"
        return "    "

    def _line_indent_at(self, s: str, pos: int) -> str:
        b = s.rfind("\n", 0, pos) + 1
        e = b
        while e < len(s) and s[e] in (" ", "\t"):
            e += 1
        return s[b:e]

    def _is_word_boundary(self, s: str, idx: int) -> bool:
        if idx < 0 or idx >= len(s):
            return True
        return not (s[idx].isalnum() or s[idx] == '_')

    def _scan_string_literal(self, s: str, i: int) -> Tuple[str, int]:
        q, esc, j = s[i], False, i + 1
        while j < len(s):
            c = s[j]
            if esc:
                esc = False
            else:
                if c == '\\':
                    esc = True
                elif c == q:
                    return (s[i:j + 1], j + 1)
            j += 1
        return (s[i:j], j)

    def _strip_comments_and_preserve_strings(self, s: str) -> str:
        out, i, n = [], 0, len(s)
        while i < n:
            c = s[i]
            if c in ("'", '"'):
                lit, j = self._scan_string_literal(s, i)
                out.append(lit); i = j; continue
            if c == '/' and i + 1 < n:
                if s[i + 1] == '/':
                    while i < n and s[i] != '\n': i += 1
                    continue
                if s[i + 1] == '*':
                    j = s.find("*/", i + 2)
                    i = n if j == -1 else j + 2
                    continue
            out.append(c); i += 1
        return "".join(out)

    def _find_matching(self, s: str, start: int, open_ch: str, close_ch: str) -> int:
        i, depth = start + 1, 1
        n = len(s)
        while i < n:
            c = s[i]
            if c in ("'", '"'):
                _, i = self._scan_string_literal(s, i); continue
            if c == '/' and i + 1 < n: # 주석 처리
                if s[i+1] == '/': 
                    while i < n and s[i] != '\n': i += 1
                    continue
                if s[i+1] == '*':
                    j = s.find("*/", i+2)
                    i = n if j == -1 else j+2
                    continue
            if c == open_ch: depth += 1
            elif c == close_ch:
                depth -= 1
                if depth == 0: return i
            i += 1
        return n # Not found (fallback)

    def _find_stmt_end(self, s: str, i: int) -> int:
        n = len(s)
        while i < n:
            c = s[i]
            if c in ("'", '"'):
                _, i = self._scan_string_literal(s, i); continue
            if c in "([{":
                close = {'(' : ')', '[':']', '{':'}'}[c]
                i = self._find_matching(s, i, c, close) + 1; continue
            if c == ';': return i
            i += 1
        return n - 1

    def _extract_block_or_stmt(self, s: str, i: int) -> Tuple[str, int]:
        n = len(s)
        while i < n and s[i].isspace(): i += 1
        if i < n and s[i] == '{':
            r = self._find_matching(s, i, '{', '}')
            return (s[i:r + 1], r + 1)
        end = self._find_stmt_end(s, i)
        return ("{ " + s[i:end + 1].strip() + " }", end + 1)

    def _split_top_level_statements(self, body: str) -> List[str]:
        i, n, out, st = 0, len(body), [], 0
        while i < n:
            c = body[i]
            if c in ("'", '"'):
                _, i = self._scan_string_literal(body, i); continue
            if c in "([{":
                close = {'(' : ')', '[':']', '{':'}'}[c]
                i = self._find_matching(body, i, c, close) + 1; continue
            if c == ';':
                out.append(body[st:i + 1]); st = i + 1
            i += 1
        tail = body[st:]
        if tail.strip(): out.append(tail)
        return out
        
    def _split_top_level_chunks(self, s: str) -> List[str]:
        """
        파일 전체를 top-level 단위(함수, 전역변수 등)로 리스트 분할.
        중괄호 {} 밸런스를 기준으로 최상위 블록을 끊어냄.
        """
        chunks = []
        i, start, n = 0, 0, len(s)
        depth = 0
        while i < n:
            c = s[i]
            if c in ("'", '"'):
                _, i = self._scan_string_literal(s, i); continue
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    # Top-level 블록 종료 (함수 끝)
                    chunks.append(s[start:i+1])
                    start = i + 1
            elif c == ';' and depth == 0:
                # Top-level 선언문 종료 (전역 변수, 프로토타입 등)
                chunks.append(s[start:i+1])
                start = i + 1
            i += 1
        if start < n:
            chunks.append(s[start:])
        return chunks

    def _split_for_header(self, header: str) -> Tuple[str, str, str]:
        parts, buf, depth, i = [], [], 0, 0
        while i < len(header):
            c = header[i]
            if c in ("'", '"'):
                lit, j = self._scan_string_literal(header, i)
                buf.append(lit); i = j; continue
            if c in "([{": depth += 1
            elif c in ")]}": depth -= 1
            if c == ';' and depth == 0 and len(parts) < 2:
                parts.append("".join(buf).strip()); buf = []
            else:
                buf.append(c)
            i += 1
        parts.append("".join(buf).strip())
        while len(parts) < 3: parts.append("")
        init, cond, step = parts
        cond = cond if cond else "1"
        return init, cond, step

    # ===== Core Logic: Recursive Transform =====
    def _transform_recursive(self, s: str) -> str:
        """
        Loops, If-Else, Normalize를 하나의 패스 안에서 수행하되,
        내부 블록이 발견되면 즉시 재귀 호출하여 깊이 우선으로 처리함.
        """
        i, n, out = 0, len(s), []
        
        while i < n:
            # 1. Loop -> If/Goto
            if s.startswith("while", i) and self._is_word_boundary(s, i-1) and self._is_word_boundary(s, i+5):
                base = self._line_indent_at(s, i)
                j = i + 5
                while j < n and s[j].isspace(): j += 1
                if j < n and s[j] == '(':
                    r = self._find_matching(s, j, '(', ')')
                    cond = s[j + 1:r].strip()
                    k = r + 1
                    block, after = self._extract_block_or_stmt(s, k)
                    
                    # [Recursion] 내부 블록 먼저 처리
                    inner_content = block.strip()[1:-1]
                    inner_processed = self._transform_recursive(inner_content)
                    inner_norm = self._reindent_block_relative(inner_processed, base + self.INDENT)
                    
                    lab = self._gen_label("LOOP")
                    out.append(f"{base}{lab}:\n")
                    out.append(f"{base}if ({cond}) {{\n")
                    if inner_norm.strip():
                        out.append(inner_norm if inner_norm.endswith("\n") else inner_norm + "\n")
                    out.append(f"{base}{self.INDENT}goto {lab};\n")
                    out.append(f"{base}}}\n")
                    i = after; continue

            if s.startswith("for", i) and self._is_word_boundary(s, i-1) and self._is_word_boundary(s, i+3):
                base = self._line_indent_at(s, i)
                j = i + 3
                while j < n and s[j].isspace(): j += 1
                if j < n and s[j] == '(':
                    r = self._find_matching(s, j, '(', ')')
                    init, cond, step = self._split_for_header(s[j + 1:r])
                    k = r + 1
                    block, after = self._extract_block_or_stmt(s, k)
                    
                    # [Recursion]
                    inner_content = block.strip()[1:-1]
                    inner_processed = self._transform_recursive(inner_content)
                    inner_norm = self._reindent_block_relative(inner_processed, base + self.INDENT)
                    
                    lab = self._gen_label("LOOP")
                    init_s = (init + ";") if init and not init.strip().endswith(";") else init
                    step_s = (step + ";") if step and not step.strip().endswith(";") else step
                    if init_s: out.append(f"{base}{init_s}\n")
                    out.append(f"{base}{lab}:\n")
                    out.append(f"{base}if ({cond if cond else '1'}) {{\n")
                    if inner_norm.strip():
                        out.append(inner_norm if inner_norm.endswith("\n") else inner_norm + "\n")
                    if step_s:
                        out.append(f"{base}{self.INDENT}{step_s}\n")
                    out.append(f"{base}{self.INDENT}goto {lab};\n")
                    out.append(f"{base}}}\n")
                    i = after; continue

            # 2. If 처리 (Else 분리 + Flattening)
            if s.startswith("if", i) and self._is_word_boundary(s, i-1) and self._is_word_boundary(s, i+2):
                base = self._line_indent_at(s, i)
                j = i + 2
                while j < n and s[j].isspace(): j += 1
                if j < n and s[j] == '(':
                    r = self._find_matching(s, j, '(', ')')
                    cond = s[j + 1:r].strip()
                    k = r + 1
                    
                    # if body 추출
                    if_block_raw, after_if = self._extract_block_or_stmt(s, k)
                    
                    # else 체크
                    t = after_if
                    while t < n and s[t].isspace(): t += 1
                    has_else = False
                    else_block_raw = ""
                    after_all = after_if
                    
                    if s.startswith("else", t) and self._is_word_boundary(s, t-1) and self._is_word_boundary(s, t+4):
                        has_else = True
                        t2 = t + 4
                        while t2 < n and s[t2].isspace(): t2 += 1
                        else_block_raw, after_all = self._extract_block_or_stmt(s, t2)

                    # [Recursion] If/Else 내부 각각 재귀 처리
                    if_inner = if_block_raw.strip()[1:-1]
                    if_processed = self._transform_recursive(if_inner)
                    
                    if has_else:
                        else_inner = else_block_raw.strip()[1:-1]
                        else_processed = self._transform_recursive(else_inner)
                        
                        # Else가 있으면 -> 두 개의 If로 분리 (Logic 4)
                        # if (A) { ... } 
                        # if (!A) { ... }
                        # 여기서 분리된 각각의 If는 아래의 Flattening 로직을 타기 위해
                        # 재귀적으로 다시 string을 구성해서 out에 넣지 않고,
                        # 현재 위치에서 Flattening 로직을 적용해야 함.
                        
                        # 편의상 두 개의 If문 문자열을 만들고, 그것을 다시 parse할 수도 있지만
                        # 성능을 위해 바로 Flattening 로직 함수를 호출
                        out.append(self._flatten_single_if(base, cond, if_processed))
                        out.append(self._flatten_single_if(base, f"!({cond})", else_processed))
                    else:
                        # Else 없으면 -> 단일 If Flattening (Logic 5)
                        out.append(self._flatten_single_if(base, cond, if_processed))
                    
                    i = after_all
                    continue
            
            # 일반 문자
            out.append(s[i])
            i += 1
            
        return "".join(out)

    def _flatten_single_if(self, base: str, cond: str, inner_processed: str) -> str:
        """
        이미 내부가 처리된(recursive done) if 블록을 받아서
        한 줄이어야만 유지하고, 아니면 goto로 찢는 로직
        """
        stmts = self._split_top_level_statements(inner_processed)
        nonempty = [x for x in stmts if x.strip(';').strip()]

        # 1문장이고, 그 문장 내부에 개행이 없다면 -> 한 줄 유지
        if len(nonempty) == 1 and "\n" not in nonempty[0]:
            single = nonempty[0].strip()
            if not single.endswith(";") and not single.endswith("}"):
                single += ";"
            return f"{base}if ({cond}) {{ {single} }}\n"
        
        if len(nonempty) == 0:
            return f"{base}if ({cond}) {{ }}\n"

        # 복합 문장 -> Goto 분리
        if_label = self._gen_label("IF_L")
        else_label = self._gen_label("ELSE_L")
        
        first = (nonempty[0] or "").strip()
        rest_stmts = nonempty[1:]
        
        first_is_complex = ("\n" in first) or (("{" in first) and ("}" in first))

        buf = []
        if first_is_complex:
            buf.append(f"{base}if ({cond}) {{ goto {if_label}; }}\n")
            buf.append(f"{base}goto {else_label};\n")
            buf.append(f"{base}{if_label}:\n")
            
            all_body = "".join(nonempty)
            body_norm = self._reindent_block_relative(all_body, base)
            if body_norm.strip():
                buf.append(body_norm if body_norm.endswith("\n") else body_norm + "\n")
        else:
            fstmt = first.rstrip(';') + ";"
            buf.append(f"{base}if ({cond}) {{ {fstmt} goto {if_label}; }}\n")
            buf.append(f"{base}goto {else_label};\n")
            buf.append(f"{base}{if_label}:\n")
            
            rest = "".join(rest_stmts)
            rest_norm = self._reindent_block_relative(rest, base)
            if rest_norm.strip():
                buf.append(rest_norm if rest_norm.endswith("\n") else rest_norm + "\n")
        
        buf.append(f"{base}{else_label}:\n")
        return "".join(buf)

    # ===== Formatting Helpers =====
    def _ensure_braced_single_line_ifs(self, s: str) -> str:
        # (기존 로직과 동일 - 빠름)
        i, n, out = 0, len(s), []
        while i < n:
            if s.startswith("if", i) and self._is_word_boundary(s, i - 1) and self._is_word_boundary(s, i + 2):
                base = self._line_indent_at(s, i)
                j = i + 2
                while j < n and s[j].isspace(): j += 1
                if j < n and s[j] == '(':
                    r = self._find_matching(s, j, '(', ')')
                    k = r + 1
                    while k < n and s[k].isspace(): k += 1
                    if k < n and s[k] == '{':
                        rbrace = self._find_matching(s, k, '{', '}')
                        out.append(s[i:rbrace + 1]); i = rbrace + 1; continue
                    end = self._find_stmt_end(s, k)
                    cond = s[j + 1:r].strip()
                    stmt = s[k:end + 1].strip()
                    out.append(f"{base}if ({cond}) {{ {stmt} }}\n")
                    i = end + 1; continue
            out.append(s[i]); i += 1
        return "".join(out)

    def _compact_simple_braced_ifs(self, s: str) -> str:
        # (기존 로직과 동일)
        i, n, out = 0, len(s), []
        while i < n:
            if s.startswith("if", i) and self._is_word_boundary(s, i - 1) and self._is_word_boundary(s, i + 2):
                base = self._line_indent_at(s, i)
                j = i + 2
                while j < n and s[j].isspace(): j += 1
                if j < n and s[j] == '(':
                    r = self._find_matching(s, j, '(', ')')
                    k = r + 1
                    while k < n and s[k].isspace(): k += 1
                    if k < n and s[k] == '{':
                        rb = self._find_matching(s, k, '{', '}')
                        body = s[k + 1:rb].strip()
                        stmts = self._split_top_level_statements(body)
                        nonempty = [x for x in stmts if x.strip(';').strip()]
                        if len(nonempty) == 1 and "\n" not in nonempty[0]:
                            stmt = nonempty[0].strip()
                            if not stmt.endswith(";") and not stmt.endswith("}"):
                                stmt += ";"
                            out.append(f"{base}if ({s[j+1:r].strip()}) {{ {stmt} }}\n")
                            i = rb + 1; continue
                        out.append(s[i:rb + 1]); i = rb + 1; continue
            out.append(s[i]); i += 1
        return "".join(out)

    def _reindent_whole_code(self, s: str, label_column0: bool = True) -> str:
        lines = s.splitlines()
        level = 0
        IND = self.INDENT
        out = []
        for raw in lines:
            line = raw.rstrip("\r\n")
            stripped = line.lstrip(" \t")
            is_label = False
            if stripped.endswith(":"):
                head = stripped[:-1].strip()
                if head and re.match(r'^[A-Za-z_]\w*$', head) and not head.startswith("case") and head != "default":
                    is_label = True
            opens = line.count("{")
            closes = line.count("}")
            single_line_block = ("{" in line and "}" in line and opens == closes)
            leading_closing = stripped.startswith("}") and not single_line_block
            if leading_closing and level > 0:
                level -= 1
            if is_label and label_column0: prefix = ""
            else: prefix = IND * max(level, 0)
            out.append(prefix + stripped)
            if not single_line_block:
                delta = opens - closes
                if leading_closing: delta = opens - (closes - 1)
                level += delta
                if level < 0: level = 0
        return "\n".join(out) + ("\n" if s.endswith("\n") else "")
        
    def _reindent_block_relative(self, text: str, target: str) -> str:
        lines = text.splitlines(True)
        def lead_len(ln: str) -> int:
            j, c = 0, 0
            while j < len(ln) and ln[j] in (" ", "\t"): j += 1; c += 1
            return c
        min_lead = None
        for ln in lines:
            raw = ln.rstrip("\r\n")
            if raw.strip() == "": continue
            l = lead_len(raw)
            if min_lead is None or l < min_lead: min_lead = l
        if min_lead is None: return "".join(lines)
        out = []
        for ln in lines:
            end_nl = "\n" if ln.endswith("\n") else ""
            raw = ln.rstrip("\r\n")
            if raw.strip() == "": out.append(ln); continue
            j, cut = 0, 0
            while j < len(raw) and cut < min_lead and raw[j] in (" ", "\t"):
                j += 1; cut += 1
            out.append(target + raw[j:] + end_nl)
        return "".join(out)

if __name__ == "__main__":
    # Windows에서 multiprocessing 사용 시 필수
    multiprocessing.freeze_support()
    
    with open("../hyperkenken.c", "r") as f:
        code = f.read()
    
    pp = Preprocesser(content=code, out_path="main.pp.c").preprocess()
    pp.build()