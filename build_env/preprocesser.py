import re
from typing import Tuple, List

class Preprocesser:
    def __init__(self, content=None, file_path=None, out_path=None):
        if content is not None:
            self.content = content
        elif file_path:
            with open(file_path, "r", encoding="utf-8") as f:
                self.content = f.read()
        else:
            raise RuntimeError("Either file content or file path is essential")

        self.out_path = out_path
        self.result = ""
        self._label_id = 0
        self.INDENT = self._detect_indent_unit(self.content)  # "\t" or "    "

    # ===== Public API =====
    def get(self):
        return self.result

    def preprocess(self):
        s = self._strip_comments_and_preserve_strings(self.content)

        # 1) 단문 if를 반드시 한 줄로:  if (...) stmt;  =>  if (...) { stmt; }
        s = self._ensure_braced_single_line_ifs(s)

        # 2) 블록이 단문인 if도 한 줄로 압축:  if (...) { stmt; }  (여러 줄 아니면)
        s = self._compact_simple_braced_ifs(s)

        # 3) while/for → if+goto
        s = self._transform_loops_to_if_goto(s)

        # 4) if ... else ... → 두 개의 if
        s = self._rewrite_if_else_to_two_ifs(s)

        # 5) if 블록 정규화 (첫 문장 + goto / 라벨)
        s = self._normalize_if_blocks(s)

        # 6) 전체 재들여쓰기(안정화). 라벨은 칼럼 0 고정(원하면 False로 바꿔도 됨)
        s = self._reindent_whole_code(s, label_column0=True)

        self.result = s
        return self

    def build(self):
        if not self.out_path:
            raise RuntimeError("output file must be provided")
        with open(self.out_path, "w", encoding="utf-8") as f:
            f.write(self.result)

    # ===== Utilities =====
    def _gen_label(self, base: str) -> str:
        self._label_id += 1
        return f"{base}_{self._label_id:05d}"

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
                    while i < n and s[i] != '\n':
                        i += 1
                    continue
                if s[i + 1] == '*':
                    j = s.find("*/", i + 2)
                    i = n if j == -1 else j + 2
                    continue
            out.append(c); i += 1
        return "".join(out)

    def _find_matching(self, s: str, start: int, open_ch: str, close_ch: str) -> int:
        assert s[start] == open_ch
        i, depth = start + 1, 1
        while i < len(s):
            c = s[i]
            if c in ("'", '"'):
                _, i = self._scan_string_literal(s, i)
                continue
            if c == '/' and i + 1 < len(s):
                if s[i + 1] == '/':
                    while i < len(s) and s[i] != '\n':
                        i += 1
                    continue
                if s[i + 1] == '*':
                    j = s.find("*/", i + 2)
                    i = len(s) if j == -1 else j + 2
                    continue
            if c == open_ch:
                depth += 1
            elif c == close_ch:
                depth -= 1
                if depth == 0:
                    return i
            i += 1
        raise ValueError(f"Unbalanced {open_ch}{close_ch} at {start}")

    def _find_stmt_end(self, s: str, i: int) -> int:
        n = len(s)
        while i < n:
            c = s[i]
            if c in ("'", '"'):
                _, i = self._scan_string_literal(s, i); continue
            if c in "([{":
                close = {'(' : ')', '[':']', '{':'}'}[c]
                i = self._find_matching(s, i, c, close) + 1; continue
            if c == ';':
                return i
            i += 1
        return n - 1

    def _extract_block_or_stmt(self, s: str, i: int) -> Tuple[str, int]:
        n = len(s)
        while i < n and s[i].isspace():
            i += 1
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
        if tail.strip():
            out.append(tail if tail.rstrip().endswith(';') else tail + "\n")
        return out

    def _reindent_block_relative(self, text: str, target: str) -> str:
        lines = text.splitlines(True)

        def lead_len(ln: str) -> int:
            j, c = 0, 0
            while j < len(ln) and ln[j] in (" ", "\t"):
                j += 1; c += 1
            return c

        min_lead = None
        for ln in lines:
            raw = ln.rstrip("\r\n")
            if raw.strip() == "":
                continue
            l = lead_len(raw)
            if min_lead is None or l < min_lead:
                min_lead = l
        if min_lead is None:
            return "".join(lines)
        out = []
        for ln in lines:
            end_nl = "\n" if ln.endswith("\n") else ""
            raw = ln.rstrip("\r\n")
            if raw.strip() == "":
                out.append(ln); continue
            j, cut = 0, 0
            while j < len(raw) and cut < min_lead and raw[j] in (" ", "\t"):
                j += 1; cut += 1
            out.append(target + raw[j:] + end_nl)
        return "".join(out)

    # ===== 1) if (...) stmt; → if (...) { stmt; } (한 줄 강제) =====
    def _ensure_braced_single_line_ifs(self, s: str) -> str:
        i, n, out = 0, len(s), []
        while i < n:
            if s.startswith("if", i) and self._is_word_boundary(s, i - 1) and self._is_word_boundary(s, i + 2):
                base = self._line_indent_at(s, i)
                j = i + 2
                while j < n and s[j].isspace():
                    j += 1
                if j < n and s[j] == '(':
                    r = self._find_matching(s, j, '(', ')')
                    k = r + 1
                    while k < n and s[k].isspace():
                        k += 1
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

    # ===== 2) if (...) { <단문>; } → 한 줄 압축 =====
    def _compact_simple_braced_ifs(self, s: str) -> str:
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
                            if not stmt.endswith(";"):
                                stmt += ";"
                            out.append(f"{base}if ({s[j+1:r].strip()}) {{ {stmt} }}\n")
                            i = rb + 1; continue
                        out.append(s[i:rb + 1]); i = rb + 1; continue
            out.append(s[i]); i += 1
        return "".join(out)

    # ===== 3) while/for → if+goto =====
    def _transform_loops_to_if_goto(self, s: str) -> str:
        i, n, out = 0, len(s), []
        while i < n:
            # while
            if s.startswith("while", i) and self._is_word_boundary(s, i - 1) and self._is_word_boundary(s, i + 5):
                base = self._line_indent_at(s, i)
                j = i + 5
                while j < n and s[j].isspace(): j += 1
                if j < n and s[j] == '(':
                    r = self._find_matching(s, j, '(', ')')
                    cond = s[j + 1:r].strip()
                    k = r + 1
                    while k < n and s[k].isspace(): k += 1
                    if k < n and s[k] == '{':
                        rb = self._find_matching(s, k, '{', '}')
                        inner = s[k + 1:rb]; i = rb + 1
                    else:
                        end = self._find_stmt_end(s, k)
                        inner = s[k:end + 1]; i = end + 1
                    lab = self._gen_label("LOOP")
                    inner_norm = self._reindent_block_relative(inner, base + self.INDENT)
                    out.append(f"{base}{lab}:\n")
                    out.append(f"{base}if ({cond}) {{\n")
                    if inner_norm.strip():
                        out.append(inner_norm if inner_norm.endswith("\n") else inner_norm + "\n")
                    out.append(f"{base}{self.INDENT}goto {lab};\n")
                    out.append(f"{base}}}\n")
                    continue
            # for
            if s.startswith("for", i) and self._is_word_boundary(s, i - 1) and self._is_word_boundary(s, i + 3):
                base = self._line_indent_at(s, i)
                j = i + 3
                while j < n and s[j].isspace(): j += 1
                if j < n and s[j] == '(':
                    r = self._find_matching(s, j, '(', ')')
                    init, cond, step = self._split_for_header(s[j + 1:r])
                    k = r + 1
                    while k < n and s[k].isspace(): k += 1
                    if k < n and s[k] == '{':
                        rb = self._find_matching(s, k, '{', '}')
                        inner = s[k + 1:rb]; i = rb + 1
                    else:
                        end = self._find_stmt_end(s, k)
                        inner = s[k:end + 1]; i = end + 1
                    lab = self._gen_label("LOOP")
                    init_s = (init + ";") if init and not init.strip().endswith(";") else init
                    step_s = (step + ";") if step and not step.strip().endswith(";") else step
                    if init_s: out.append(f"{base}{init_s}\n")
                    inner_norm = self._reindent_block_relative(inner, base + self.INDENT)
                    out.append(f"{base}{lab}:\n")
                    out.append(f"{base}if ({cond if cond else '1'}) {{\n")
                    if inner_norm.strip():
                        out.append(inner_norm if inner_norm.endswith("\n") else inner_norm + "\n")
                    if step_s:
                        out.append(f"{base}{self.INDENT}{step_s}\n")
                    out.append(f"{base}{self.INDENT}goto {lab};\n")
                    out.append(f"{base}}}\n")
                    continue
            out.append(s[i]); i += 1
        return "".join(out)

    def _split_for_header(self, header: str) -> Tuple[str, str, str]:
        parts, buf, depth, i = [], [], 0, 0
        while i < len(header):
            c = header[i]
            if c in ("'", '"'):
                lit, j = self._scan_string_literal(header, i)
                buf.append(lit); i = j; continue
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            if c == ';' and depth == 0 and len(parts) < 2:
                parts.append("".join(buf).strip()); buf = []
            else:
                buf.append(c)
            i += 1
        parts.append("".join(buf).strip())
        while len(parts) < 3:
            parts.append("")
        init, cond, step = parts
        cond = cond if cond else "1"
        return init, cond, step

    # ===== 4) if ... else ... → 두 개의 if =====
    def _rewrite_if_else_to_two_ifs(self, s: str) -> str:
        i, n, out = 0, len(s), []
        while i < n:
            if s.startswith("if", i) and self._is_word_boundary(s, i - 1) and self._is_word_boundary(s, i + 2):
                base = self._line_indent_at(s, i)
                j = i + 2
                while j < n and s[j].isspace(): j += 1
                if j < n and s[j] == '(':
                    r = self._find_matching(s, j, '(', ')')
                    cond = s[j + 1:r].strip()
                    k = r + 1
                    if_block, after_if = self._extract_block_or_stmt(s, k)
                    t = after_if
                    while t < n and s[t].isspace(): t += 1
                    if s.startswith("else", t) and self._is_word_boundary(s, t - 1) and self._is_word_boundary(s, t + 4):
                        t2 = t + 4
                        while t2 < n and s[t2].isspace(): t2 += 1
                        else_block, after = self._extract_block_or_stmt(s, t2)
                        out.append(f"{base}if ({cond}) {if_block}\n")
                        out.append(f"{base}if (!({cond})) {else_block}\n")
                        i = after; continue
                    else:
                        out.append(f"{base}if ({cond}) {if_block}\n")
                        i = after_if; continue
            out.append(s[i]); i += 1
        return "".join(out)

    # ===== 5) if 블록 정규화 =====
    def _normalize_if_blocks(self, s: str) -> str:
        i, n, out = 0, len(s), []
        while i < n:
            if s.startswith("if", i) and self._is_word_boundary(s, i - 1) and self._is_word_boundary(s, i + 2):
                base = self._line_indent_at(s, i)
                j = i + 2
                while j < n and s[j].isspace(): j += 1
                if j < n and s[j] == '(':
                    r = self._find_matching(s, j, '(', ')')
                    cond = s[j + 1:r].strip()
                    k = r + 1
                    block, after = self._extract_block_or_stmt(s, k)
                    inner = block.strip()[1:-1]
                    stmts = self._split_top_level_statements(inner)
                    nonempty = [x for x in stmts if x.strip(';').strip()]

                    # 1문장 → 무조건 한 줄 if
                    if len(nonempty) == 1 and "\n" not in nonempty[0]:
                        single = nonempty[0].strip()
                        if not single.endswith(";"):
                            single += ";"
                        out.append(f"{base}if ({cond}) {{ {single} }}\n")
                        i = after; continue

                    # 0/1개(중첩 블록 한 개 등) → 멀티라인 유지
                    if len(nonempty) <= 1:
                        inner_norm = self._reindent_block_relative(inner, base + self.INDENT)
                        out.append(f"{base}if ({cond}) {{\n{inner_norm}{base}}}\n")
                        i = after; continue

                    # 2문장 이상 → 첫 문장 + goto, 나머지는 라벨 아래
                    if_label = self._gen_label("IF_L")
                    else_label = self._gen_label("ELSE_L")
                    first = (stmts[0] or "").strip()
                    rest = "".join(stmts[1:])

                    # 첫 문장에 개행/블록이 있으면 멀티라인로 출력
                    first_is_multiline = ("\n" in first) or (("{" in first) and ("}" in first) and ("\n" in first))
                    if first_is_multiline:
                        first_norm = self._reindent_block_relative(first, base + self.INDENT)
                        out.append(f"{base}if ({cond}) {{\n")
                        out.append(first_norm if first_norm.endswith("\n") else first_norm + "\n")
                        out.append(f"{base}{self.INDENT}goto {if_label};\n")
                        out.append(f"{base}}}\n")
                    else:
                        fstmt = first.rstrip(';') + ";"
                        out.append(f"{base}if ({cond}) {{ {fstmt} goto {if_label}; }}\n")

                    out.append(f"{base}goto {else_label};\n")
                    out.append(f"{base}{if_label}:\n")
                    rest_norm = self._reindent_block_relative(rest, base)
                    if rest_norm.strip():
                        out.append(rest_norm if rest_norm.endswith("\n") else rest_norm + "\n")
                    out.append(f"{base}{else_label}:\n")
                    i = after; continue
            out.append(s[i]); i += 1
        return "".join(out)

    # ===== 6) 전체 재들여쓰기 =====
    def _reindent_whole_code(self, s: str, label_column0: bool = True) -> str:
        """
        - 중괄호 기반 레벨 계산
        - 한 줄 블록 `{ ... }`은 레벨 변화 없음
        - 라벨 `<ident>:`은 label_column0=True면 칼럼 0, 아니면 현재 레벨에 맞춤
        """
        lines = s.splitlines()
        level = 0
        IND = self.INDENT
        out = []

        for raw in lines:
            line = raw.rstrip("\r\n")
            stripped = line.lstrip(" \t")

            # 라벨인지 확인 (case/default 제외)
            is_label = False
            if stripped.endswith(":"):
                head = stripped[:-1].strip()
                if head and re.match(r'^[A-Za-z_]\w*$', head) and not head.startswith("case") and head != "default":
                    is_label = True

            # 한 줄 블록?
            opens = line.count("{")
            closes = line.count("}")
            single_line_block = ("{" in line and "}" in line and opens == closes)

            # 선행 '}' 라인이면 먼저 감소
            leading_closing = stripped.startswith("}") and not single_line_block
            if leading_closing and level > 0:
                level -= 1

            # 들여쓰기 접두
            if is_label and label_column0:
                prefix = ""
            else:
                prefix = IND * max(level, 0)

            out.append(prefix + stripped)

            # 라인 후 레벨 조정
            if not single_line_block:
                delta = opens - closes
                if leading_closing:
                    delta = opens - (closes - 1)
                level += delta
                if level < 0:
                    level = 0

        return "\n".join(out) + ("\n" if s.endswith("\n") else "")

# test
if __name__ == "__main__":
    with open("main.c", "r") as f:
        code = f.read()
    
    pp = Preprocesser(content=code, out_path="main.pp.c").preprocess()
    pp.build()