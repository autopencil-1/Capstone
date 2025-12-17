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
        self.INDENT = "    " # 들여쓰기는 가독성용일 뿐, 로직엔 영향 없음

    def get(self):
        return self.result

    def preprocess(self):
        # 1. 주석 제거 및 문자열 보존
        code = self._strip_comments_and_preserve_strings(self.content)
        
        # 2. 재귀적 변환 (핵심 로직)
        # 전체 코드를 하나의 블록으로 보고 변환 시작
        self.result = self._process_block(code)
        return self

    def build(self):
        if not self.out_path:
            raise RuntimeError("output file must be provided")
        with open(self.out_path, "w", encoding="utf-8") as f:
            f.write(self.result)

    # ===== Core Logic: Recursive Descent Parser =====
    def _process_block(self, text: str) -> str:
        """
        텍스트를 순차적으로 읽으면서 if/for/while을 만나면 
        내부를 재귀적으로 처리하고 goto 구조로 변환하여 리턴합니다.
        (조건절 내부의 개행 문자도 제거하여 완벽한 한 줄을 보장합니다)
        """
        out = []
        i, n = 0, len(text)
        
        while i < n:
            # 공백 건너뛰기
            if text[i].isspace():
                out.append(text[i])
                i += 1
                continue

            # 1. IF 문 발견
            if text.startswith("if", i) and self._is_word_boundary(text, i, 2):
                base_indent = self._get_indent(text, i)
                
                # 조건문 (...) 파싱
                j = i + 2
                while j < n and text[j].isspace(): j += 1
                if j < n and text[j] == '(':
                    cond_end = self._find_matching(text, j, '(', ')')
                    # [FIX] 조건식 내부의 줄바꿈을 공백으로 치환하여 한 줄 강제
                    cond = text[j+1:cond_end].strip().replace('\n', ' ').replace('\r', ' ')
                    
                    # 본문 {...} 또는 문장 파싱
                    k = cond_end + 1
                    # [중요] extract_control_structure를 사용하여 else if 체인까지 포함
                    body_str, next_idx = self._extract_control_structure(text, i) 
                    
                    # _extract_control_structure는 if (...) { ... } 전체를 가져오므로,
                    # 우리가 필요한 건 '본문' 내용입니다.
                    # 하지만 위 함수는 구조 추출용이므로, 여기서는 로직을 살짝 분리해야 합니다.
                    # 이미 위에서 cond는 파싱했으므로, body 부분만 정확히 발라내기 위해
                    # extract_stmt_or_block을 사용하는 기존 로직 유지하되
                    # else 처리는 아래에서 수동으로 합니다.

                    # (정정) 아까 만든 _extract_control_structure는 덩어리 추출용이고,
                    # 지금 필요한 건 파싱이므로 다시 단계별로 갑니다.
                    
                    # 본문 추출
                    body_raw, next_idx = self._extract_stmt_or_block(text, k)
                    processed_body = self._process_block(body_raw)
                    
                    # Else 체크
                    else_idx = next_idx
                    while else_idx < n and text[else_idx].isspace(): else_idx += 1
                    
                    has_else = False
                    processed_else = ""
                    
                    if text.startswith("else", else_idx) and self._is_word_boundary(text, else_idx, 4):
                        has_else = True
                        e_k = else_idx + 4
                        # else 뒤의 문장/블록 추출 (else if 체인 포함)
                        else_body_raw, next_idx = self._extract_stmt_or_block(text, e_k)
                        processed_else = self._process_block(else_body_raw)

                    # 구조 변환
                    l_true = self._gen_label("IF_T")
                    l_end = self._gen_label("IF_E")
                    
                    if has_else:
                        l_else = self._gen_label("IF_F")
                        out.append(f"if ({cond}) {{ goto {l_true}; }}")
                        out.append(f"\ngoto {l_else};\n")
                        out.append(f"{l_true}: {{\n{processed_body}\n}}\ngoto {l_end};\n")
                        out.append(f"{l_else}: {{\n{processed_else}\n}}\n{l_end}:\n")
                    else:
                        out.append(f"if ({cond}) {{ goto {l_true}; }}")
                        out.append(f"\ngoto {l_end};\n")
                        out.append(f"{l_true}: {{\n{processed_body}\n}}\n{l_end}:\n")
                    
                    i = next_idx
                    continue

            # 2. WHILE 문 발견
            elif text.startswith("while", i) and self._is_word_boundary(text, i, 5):
                j = i + 5
                while j < n and text[j].isspace(): j += 1
                if j < n and text[j] == '(':
                    cond_end = self._find_matching(text, j, '(', ')')
                    # [FIX] 조건식 줄바꿈 제거
                    cond = text[j+1:cond_end].strip().replace('\n', ' ').replace('\r', ' ')
                    
                    k = cond_end + 1
                    body_str, next_idx = self._extract_stmt_or_block(text, k)
                    processed_body = self._process_block(body_str)
                    
                    l_loop = self._gen_label("W_LOOP")
                    l_body = self._gen_label("W_BODY")
                    l_end  = self._gen_label("W_END")
                    
                    out.append(f"\n{l_loop}:\n")
                    out.append(f"if ({cond}) {{ goto {l_body}; }}")
                    out.append(f"\ngoto {l_end};\n")
                    out.append(f"{l_body}: {{\n{processed_body}\n}}\ngoto {l_loop};\n{l_end}:\n")
                    
                    i = next_idx
                    continue

            # 3. FOR 문 발견
            elif text.startswith("for", i) and self._is_word_boundary(text, i, 3):
                j = i + 3
                while j < n and text[j].isspace(): j += 1
                if j < n and text[j] == '(':
                    cond_end = self._find_matching(text, j, '(', ')')
                    header = text[j+1:cond_end]
                    
                    k = cond_end + 1
                    body_str, next_idx = self._extract_stmt_or_block(text, k)
                    processed_body = self._process_block(body_str)
                    
                    # 헤더 파싱 및 줄바꿈 제거
                    init, cond, step = self._parse_for_header(header)
                    # [FIX] for문 구성요소 각각 줄바꿈 제거
                    init = init.replace('\n', ' ').replace('\r', ' ')
                    cond = cond.replace('\n', ' ').replace('\r', ' ')
                    step = step.replace('\n', ' ').replace('\r', ' ')
                    
                    l_loop = self._gen_label("F_LOOP")
                    l_body = self._gen_label("F_BODY")
                    l_end = self._gen_label("F_END")
                    
                    if init: out.append(f"{init};\n")
                    out.append(f"{l_loop}:\n")
                    # cond가 비어있으면 1(무한루프) 처리
                    final_cond = cond if cond.strip() else '1'
                    out.append(f"if ({final_cond}) {{ goto {l_body}; }}")
                    out.append(f"\ngoto {l_end};\n")
                    
                    step_code = f"{step};" if step.strip() else ""
                    out.append(f"{l_body}: {{\n{processed_body}\n{step_code}\n}}\ngoto {l_loop};\n{l_end}:\n")
                    
                    i = next_idx
                    continue

            # 그 외 일반 문자열
            out.append(text[i])
            i += 1
            
        return "".join(out)
    
    # ===== Utilities =====
    def _gen_label(self, prefix):
        self._label_id += 1
        return f"{prefix}_{self._label_id:05d}"

    def _is_word_boundary(self, s, idx, length):
        # 키워드 뒤가 알파벳/숫자/_ 가 아니어야 함
        end_idx = idx + length
        if end_idx >= len(s): return True
        c = s[end_idx]
        return not (c.isalnum() or c == '_')

    def _get_indent(self, s, idx):
        # 현재 라인의 들여쓰기 파악 (단순 포맷팅용)
        line_start = s.rfind('\n', 0, idx) + 1
        return s[line_start:idx]

    def _extract_stmt_or_block(self, s, i):
        """
        문장 하나(;) 또는 블록({...}) 또는 제어문 전체를 추출
        """
        n = len(s)
        while i < n and s[i].isspace(): i += 1
        
        # 1. 블록인 경우 ({...})
        if i < n and s[i] == '{':
            end = self._find_matching(s, i, '{', '}')
            return s[i+1:end], end + 1 # 중괄호 제외한 내용 리턴

        # 2. 제어문인 경우 (if, for, while, switch)
        # 이들은 세미콜론 없이 {...} 블록으로 끝날 수도 있음
        for kw in ["if", "for", "while", "switch"]:
            if s.startswith(kw, i) and self._is_word_boundary(s, i, len(kw)):
                return self._extract_control_structure(s, i)

        # 3. 일반 문장 (단순 세미콜론 종료)
        # 단, 괄호 깊이를 고려하여 탐색
        end = self._find_stmt_end(s, i)
        return s[i:end+1], end + 1
    
    def _extract_control_structure(self, s, start):
        """
        if/for/while 등의 제어문이 어디서 끝나는지 파악하여 추출
        if문의 경우, 뒤따르는 else 절까지 포함하여 추출함 (중요!)
        """
        i = start
        n = len(s)
        
        # 1. 키워드 확인 (if인지 기록)
        is_if = False
        if s.startswith("if", i) and self._is_word_boundary(s, i, 2):
            is_if = True
            
        # 키워드 건너뛰기
        while i < n and s[i].isalnum(): i += 1
        while i < n and s[i].isspace(): i += 1
        
        # 2. 조건절 (...) 건너뛰기
        if i < n and s[i] == '(':
            i = self._find_matching(s, i, '(', ')') + 1
        
        while i < n and s[i].isspace(): i += 1
        
        # 3. 본문 확인 (if의 True 블록)
        if i < n and s[i] == '{':
            end = self._find_matching(s, i, '{', '}')
            i = end + 1
        else:
            end = self._find_stmt_end(s, i)
            i = end + 1
            
        # 4. [FIX] 만약 if문이었다면, 뒤에 else가 있는지 확인하여 확장
        if is_if:
            # 공백 건너뛰기
            tmp = i
            while tmp < n and s[tmp].isspace(): tmp += 1
            
            # else 감지
            if s.startswith("else", tmp) and self._is_word_boundary(s, tmp, 4):
                # else 키워드 건너뛰기
                tmp += 4
                # else 뒤에 오는 문장/블록 추출 (재귀적으로 else if 체인 전체를 가져옴)
                _, else_end = self._extract_stmt_or_block(s, tmp)
                return s[start:else_end], else_end

        return s[start:i], i

    def _find_matching(self, s, start, open_ch, close_ch):
        depth = 1
        i = start + 1
        n = len(s)
        
        while i < n:
            c = s[i]
            # 1. 문자열 건너뛰기
            if c in ('"', "'"):
                try:
                    _, i = self._scan_string(s, i)
                except Exception:
                    # 문자열이 안 닫히고 끝난 경우
                    print(f"\n[DEBUG] String literal error at index {i}")
                    print(f"Context: {s[i:i+50]}")
                    raise
                continue
            
            # 2. 괄호 카운팅
            if c == open_ch: 
                depth += 1
            elif c == close_ch:
                depth -= 1
                if depth == 0: return i
            
            i += 1
        
        # EOF 도달 시 디버깅 정보 출력
        print(f"\n[ERROR] Unbalanced {open_ch}{close_ch}")
        print(f"Start index: {start}")
        print(f"Remaining depth: {depth}")
        print(f"Code snippet starting at error: {s[start:start+200]}")
        raise ValueError(f"Unbalanced {open_ch}{close_ch}")

    def _find_stmt_end(self, s, i):
        """
        세미콜론을 찾되, 괄호/따옴표 등의 깊이를 고려하여
        최상위 레벨(depth 0)의 세미콜론을 찾음
        """
        n = len(s)
        depth_paren = 0 # ()
        depth_brace = 0 # {}
        depth_brack = 0 # []
        
        while i < n:
            c = s[i]
            
            # 문자열 건너뛰기
            if c in ('"', "'"):
                _, i = self._scan_string(s, i)
                continue
            
            # 괄호 깊이 추적
            if c == '(': depth_paren += 1
            elif c == ')': depth_paren -= 1
            elif c == '{': depth_brace += 1
            elif c == '}': depth_brace -= 1
            elif c == '[': depth_brack += 1
            elif c == ']': depth_brack -= 1
            
            # 종료 조건: 깊이가 모두 0이고 세미콜론일 때
            if c == ';' and depth_paren == 0 and depth_brace == 0 and depth_brack == 0:
                return i
            
            # 안전장치: 혹시 닫는 중괄호가 나와서 블록이 끝나버리면 거기서 멈춤 (문법 오류 방지)
            if c == '}' and depth_brace < 0:
                return i - 1

            i += 1
            
        return n - 1

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
        # for (A; B; C) 파싱
        parts = []
        buf = []
        depth = 0
        i = 0
        while i < len(header):
            c = header[i]
            if c in ('"', "'"):
                lit, j = self._scan_string(header, i)
                buf.append(lit)
                i = j
                continue
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
    import sys
    # 실행 예시
    with open("../hyperkenken.c", "r") as f:
        code = f.read()
    
    pp = Preprocesser(content=code, out_path="main.pp.c")
    pp.preprocess()
    pp.build()