import re

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
        self.INDENT = "    " 

    def get(self):
        return self.result

    def preprocess(self):
        # 1. 주석 제거
        code = self._strip_comments_and_preserve_strings(self.content)
        
        # 2. 재귀적 변환 (Context: None -> 현재 루프 없음)
        self.result = self._process_block(code, loop_ctx=None)
        return self

    def build(self):
        if not self.out_path:
            raise RuntimeError("output file must be provided")
        with open(self.out_path, "w", encoding="utf-8") as f:
            f.write(self.result)

    # ===== Core Logic =====
    
    def _process_block(self, text: str, loop_ctx=None) -> str:
        """
        loop_ctx: (continue_label, break_label) 튜플. 
                  현재 처리 중인 블록이 어떤 루프 안에 있는지 정보를 가짐.
        """
        out = []
        i, n = 0, len(text)
        
        while i < n:
            # 공백 유지
            if text[i].isspace():
                out.append(text[i])
                i += 1
                continue

            # 1. IF 문
            if text.startswith("if", i) and self._is_word_boundary(text, i, 2):
                j = i + 2
                while j < n and text[j].isspace(): j += 1
                if j < n and text[j] == '(':
                    cond_end = self._find_matching(text, j, '(', ')')
                    # 조건식 내 개행 제거
                    cond = text[j+1:cond_end].strip().replace('\n', ' ').replace('\r', ' ')
                    
                    # 본문 및 else 체인 추출
                    k = cond_end + 1
                    # [중요] loop_ctx를 그대로 전달 (if문은 루프를 끊지 않으므로)
                    body_raw, next_idx = self._extract_stmt_or_block(text, k)
                    processed_body = self._process_block(body_raw, loop_ctx)
                    
                    # Else 체크
                    else_idx = next_idx
                    while else_idx < n and text[else_idx].isspace(): else_idx += 1
                    
                    has_else = False
                    processed_else = ""
                    
                    if text.startswith("else", else_idx) and self._is_word_boundary(text, else_idx, 4):
                        has_else = True
                        e_k = else_idx + 4
                        else_body_raw, next_idx = self._extract_stmt_or_block(text, e_k)
                        processed_else = self._process_block(else_body_raw, loop_ctx)

                    # 구조 변환
                    l_true = self._gen_label("IF_T")
                    l_end = self._gen_label("IF_E")
                    
                    if has_else:
                        l_else = self._gen_label("IF_F")
                        # if (cond) { goto T; } goto F; T: { body } goto E; F: { else } E:
                        out.append(f"if ({cond}) {{ goto {l_true}; }}")
                        out.append(f"\ngoto {l_else};\n")
                        out.append(f"{l_true}: {{\n{processed_body}\n}}\ngoto {l_end};\n")
                        out.append(f"{l_else}: {{\n{processed_else}\n}}\n{l_end}:\n")
                    else:
                        # if (cond) { goto T; } goto E; T: { body } E:
                        out.append(f"if ({cond}) {{ goto {l_true}; }}")
                        out.append(f"\ngoto {l_end};\n")
                        out.append(f"{l_true}: {{\n{processed_body}\n}}\n{l_end}:\n")
                    
                    i = next_idx
                    continue

            # 2. WHILE 문
            elif text.startswith("while", i) and self._is_word_boundary(text, i, 5):
                j = i + 5
                while j < n and text[j].isspace(): j += 1
                if j < n and text[j] == '(':
                    cond_end = self._find_matching(text, j, '(', ')')
                    cond = text[j+1:cond_end].strip().replace('\n', ' ').replace('\r', ' ')
                    
                    k = cond_end + 1
                    body_raw, next_idx = self._extract_stmt_or_block(text, k)
                    
                    l_loop = self._gen_label("W_LOOP")
                    l_body = self._gen_label("W_BODY")
                    l_end  = self._gen_label("W_END")
                    
                    # [중요] 루프 내부 처리 시, 현재 라벨 정보를 컨텍스트로 전달
                    # continue -> l_loop, break -> l_end
                    processed_body = self._process_block(body_raw, loop_ctx=(l_loop, l_end))
                    
                    # while 구조 변환
                    out.append(f"\n{l_loop}:\n")
                    out.append(f"if ({cond}) {{ goto {l_body}; }}")
                    out.append(f"\ngoto {l_end};\n")
                    out.append(f"{l_body}: {{\n{processed_body}\n}}\ngoto {l_loop};\n{l_end}:\n")
                    
                    i = next_idx
                    continue

            # 3. FOR 문
            elif text.startswith("for", i) and self._is_word_boundary(text, i, 3):
                j = i + 3
                while j < n and text[j].isspace(): j += 1
                if j < n and text[j] == '(':
                    cond_end = self._find_matching(text, j, '(', ')')
                    header = text[j+1:cond_end]
                    
                    k = cond_end + 1
                    body_raw, next_idx = self._extract_stmt_or_block(text, k)
                    
                    init, cond, step = self._parse_for_header(header)
                    init = init.replace('\n', ' ').replace('\r', ' ')
                    cond = cond.replace('\n', ' ').replace('\r', ' ')
                    step = step.replace('\n', ' ').replace('\r', ' ')
                    
                    l_loop = self._gen_label("F_LOOP")
                    l_body = self._gen_label("F_BODY")
                    l_step = self._gen_label("F_STEP") # continue 시 여기로 와야 함 (step 실행)
                    l_end = self._gen_label("F_END")
                    
                    # [중요] for문은 continue 시 step 구문으로 가야 함!
                    # continue -> l_step, break -> l_end
                    processed_body = self._process_block(body_raw, loop_ctx=(l_step, l_end))
                    
                    # Scope 격리를 위해 전체를 중괄호로 감쌈
                    out.append("{\n") 
                    if init: out.append(f"{init};\n")
                    
                    out.append(f"{l_loop}:\n")
                    final_cond = cond if cond.strip() else '1'
                    out.append(f"if ({final_cond}) {{ goto {l_body}; }}")
                    out.append(f"\ngoto {l_end};\n")
                    
                    step_code = f"{step};" if step.strip() else ""
                    
                    # BODY -> STEP -> LOOP
                    out.append(f"{l_body}: {{\n{processed_body}\n}}\n")
                    out.append(f"{l_step}:\n") # continue 타겟
                    out.append(f"{step_code}\n")
                    out.append(f"goto {l_loop};\n")
                    
                    out.append(f"{l_end}:\n")
                    out.append("}\n") # Scope 닫기
                    
                    i = next_idx
                    continue

            # 4. Break / Continue 치환
            elif text.startswith("break", i) and self._is_word_boundary(text, i, 5):
                # 세미콜론 확인
                j = i + 5
                while j < n and text[j].isspace(): j += 1
                if j < n and text[j] == ';':
                    if loop_ctx:
                        # break -> goto end_label
                        out.append(f"goto {loop_ctx[1]};")
                        i = j + 1
                        continue
                    else:
                        # loop_ctx가 없으면 (switch 등) 그냥 둠
                        pass

            elif text.startswith("continue", i) and self._is_word_boundary(text, i, 8):
                j = i + 8
                while j < n and text[j].isspace(): j += 1
                if j < n and text[j] == ';':
                    if loop_ctx:
                        # continue -> goto loop_label (or step_label)
                        out.append(f"goto {loop_ctx[0]};")
                        i = j + 1
                        continue
                    else:
                        pass

            # 그 외 일반 문자열
            out.append(text[i])
            i += 1
            
        return "".join(out)

    # ===== Utilities (기존과 동일 + Scope 격리용) =====

    def _gen_label(self, prefix):
        self._label_id += 1
        return f"{prefix}_{self._label_id:05d}"

    def _is_word_boundary(self, s, idx, length):
        end_idx = idx + length
        if end_idx >= len(s): return True
        c = s[end_idx]
        return not (c.isalnum() or c == '_')

    def _extract_stmt_or_block(self, s, i):
        n = len(s)
        while i < n and s[i].isspace(): i += 1
        
        # 1. 블록
        if i < n and s[i] == '{':
            end = self._find_matching(s, i, '{', '}')
            return s[i+1:end], end + 1 # 중괄호 제외 내용
            
        # 2. 제어문 (if, for 등) 재귀적 덩어리 추출은 process 단계에서 하므로
        # 여기서는 단순히 문장 단위로 끊어주면 됨.
        # 하지만 else if 같은 건 하나의 문장으로 봐야 함. (기존 로직 유지)
        
        return self._extract_control_structure_or_stmt(s, i)

    def _extract_control_structure_or_stmt(self, s, start):
        i = start
        n = len(s)
        
        # 키워드 체크
        is_if = False
        if s.startswith("if", i) and self._is_word_boundary(s, i, 2):
            is_if = True
            
        # 키워드/조건절 건너뛰기
        while i < n and s[i].isalnum(): i += 1
        while i < n and s[i].isspace(): i += 1
        
        if i < n and s[i] == '(':
            i = self._find_matching(s, i, '(', ')') + 1
        
        while i < n and s[i].isspace(): i += 1
        
        # 본문 끝 찾기
        if i < n and s[i] == '{':
            end = self._find_matching(s, i, '{', '}')
            i = end + 1
        else:
            end = self._find_stmt_end(s, i)
            i = end + 1
            
        # if문이면 else 확장
        if is_if:
            tmp = i
            while tmp < n and s[tmp].isspace(): tmp += 1
            if s.startswith("else", tmp) and self._is_word_boundary(s, tmp, 4):
                tmp += 4
                _, else_end = self._extract_stmt_or_block(s, tmp)
                return s[start:else_end], else_end
                
        return s[start:i], i

    def _find_stmt_end(self, s, i):
        # 괄호 깊이 고려하여 세미콜론 찾기
        n = len(s)
        d_paren, d_brace, d_brack = 0, 0, 0
        while i < n:
            c = s[i]
            if c in ('"', "'"):
                _, i = self._scan_string(s, i)
                continue
            if c == '(': d_paren += 1
            elif c == ')': d_paren -= 1
            elif c == '{': d_brace += 1
            elif c == '}': d_brace -= 1
            elif c == '[': d_brack += 1
            elif c == ']': d_brack -= 1
            
            if c == ';' and d_paren == 0 and d_brace == 0 and d_brack == 0:
                return i
            if c == '}' and d_brace < 0: # Safety
                return i - 1
            i += 1
        return n - 1

    def _find_matching(self, s, start, open_ch, close_ch):
        depth = 1
        i = start + 1
        n = len(s)
        while i < n:
            c = s[i]
            if c in ('"', "'"):
                _, i = self._scan_string(s, i)
                continue
            if c == open_ch: depth += 1
            elif c == close_ch:
                depth -= 1
                if depth == 0: return i
            i += 1
        raise ValueError(f"Unbalanced {open_ch}{close_ch}")

    def _scan_string(self, s, i):
        quote = s[i]
        j = i + 1
        n = len(s)
        while j < n:
            if s[j] == '\\': j += 2; continue
            if s[j] == quote: return s[i:j+1], j + 1
            j += 1
        return s[i:j], j

    def _strip_comments_and_preserve_strings(self, s):
        out = []
        i, n = 0, len(s)
        while i < n:
            c = s[i]
            if c in ('"', "'"):
                lit, next_i = self._scan_string(s, i)
                out.append(lit)
                i = next_i
                continue
            if c == '/' and i + 1 < n:
                if s[i+1] == '/':
                    j = s.find('\n', i + 2)
                    i = j if j != -1 else n
                    continue
                if s[i+1] == '*':
                    j = s.find('*/', i + 2)
                    i = j + 2 if j != -1 else n
                    continue
            out.append(c)
            i += 1
        return "".join(out)

    def _parse_for_header(self, header):
        parts = []
        buf = []
        depth = 0
        i = 0
        while i < len(header):
            c = header[i]
            if c in ('"', "'"):
                lit, j = self._scan_string(header, i)
                buf.append(lit); i = j; continue
            if c == '(': depth += 1
            elif c == ')': depth -= 1
            
            if c == ';' and depth == 0:
                parts.append("".join(buf).strip())
                buf = []
            else:
                buf.append(c)
            i += 1
        parts.append("".join(buf).strip())
        while len(parts) < 3: parts.append("")
        return parts[0], parts[1], parts[2]

if __name__ == "__main__":
    with open("hyperkenken.c", "r") as f:
        code = f.read()
    pp = Preprocesser(content=code, out_path="main.pp.c")
    pp.preprocess()
    pp.build()