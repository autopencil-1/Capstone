from mba import gen_mba, gen_mba_cond
import random
import re
from typing import List

def indent_level(line, tabsize=4):
    m = re.match(r"^[ \t]*", line)
    if not m:
        return 0
    raw = m.group()
    return sum(tabsize if ch == '\t' else 1 for ch in raw)

class Obfuscator:
    def __init__(self,
                 src: str,
                 out: str,
                 opaque_dir: str,
                 case_cnt: int=20,
                 global_cnt: int=200,
                 obf_prob: float=0.5):
        self.src = src
        self.out = out
        self.map = dict()
        self.case_cnt = case_cnt
        self.glob_cnt = global_cnt
        self.obf_prob = obf_prob

        self.jpt_l = []

        self.opaque_dir = opaque_dir
        self.functions = set()

        with open(f"{opaque_dir}/opaque.h", "w") as f:
            f.write("#include <stdint.h>\n")
            f.write("\n")
            f.write("__attribute__((noinline))\n")
            f.write("uint64_t OPQ(const uint64_t *p);\n")
            

        with open(f"{opaque_dir}/opaque.c", "w") as f:
            f.write('#include "opaque.h"\n')
            f.write('#include "glob.h"\n')

            f.write("__attribute__((noinline))\n")
            f.write("uint64_t OPQ(const uint64_t *p) {\n")
            f.write("    volatile const uint64_t *vp = (volatile const uint64_t*)p;\n")
            f.write("    return *vp;\n")
            f.write("}\n")

            for i in range(self.glob_cnt):
                f.write(f"uint64_t G_{i};\n")

        self.add_header()
        
        self.local_iter = 0

        return
    
    def add_function(self, name: str, spec: List[str], content: List[str]):
        if name in self.functions:
            return
        
        f_str = "{ret} {name} ({args}) {{\n".format(ret=spec[0],
                                          name=name,
                                          args=(" ,".join([f"{arg} v{i}" for i, arg in enumerate(spec[1:])]))[:-2])
        with open(self.opaque_dir + "/opaque.h", "a") as f:
            f.write(f_str[:-2] + ";\n")
        f_str += "".join([f"\t{c}\n" for c in content])
        f_str += "}\n"
        
        with open(self.opaque_dir + "/opaque.c", "a") as f:
            f.write(f_str)
        
        return

    def add_header(self):
        with open(f"{self.opaque_dir}/glob.h", "w") as f:
            f.write("#include <stdint.h>\n")
            for cnt in range(self.glob_cnt):
                f.write(f"extern uint64_t G_{cnt};\n")
        return

    def obf_line(self, line: str, is_if = False):
        """
        one line -> obfuscated lines
        """
        indent = indent_level(line)
        if indent == 0:
            return line
        line_raw = line.strip()
        
        # select global variables
        globs = random.sample(range(0, self.glob_cnt), 3)
        const_glob = globs[0]
        var_glob1 = globs[1]
        var_glob2 = globs[2]
        const_val = random.randint(0, (1<<64)-1)
        out = random.randint(0, (1<<64)-1)
        out2 = random.randint(0, (1<<64)-1)

        # set const global variable
        spec = ["void"]
        content = [f"G_{const_glob} = {const_val}ULL;"]
        self.add_function(f"set_glob_{const_glob}_{const_val}", spec=spec, content=content)

        # gen MBA function
        if is_if:
            expr = gen_mba_cond(
                inp=[None, None, None],
                out_zero=out2,
                out_nonzero=out,
                gate_idx=1,
                pick_when="nonzero",
                n_const_terms=3, n_zero_terms=3, opaque_mode="volatile"
            )
            content = ["return " + expr.replace("v0", f"G_{const_glob}").replace("v1", f"G_{var_glob1}").replace("v2", f"G_{var_glob2}") + ";"]
            self.add_function(name=f"mba_{const_glob}_{const_val}_{var_glob1}_{var_glob2}_{out}_{out2}",
                            spec=["uint64_t"],
                            content=content)
        else:
            expr = gen_mba([const_val, None, None], out=out)
            content = ["return " + expr.replace("v0", f"G_{const_glob}").replace("v1", f"G_{var_glob1}").replace("v2", f"G_{var_glob2}") + ";"]
            self.add_function(name=f"mba_{const_glob}_{const_val}_{var_glob1}_{var_glob2}_{out}",
                            spec=["uint64_t"],
                            content=content)
        
        # gen obfuscated lines
        obf_lines = []

        if is_if:
            pattern = r'^if\s*\((?P<cond>.*?)\)\s*\{\s*(?P<body>.*?)\s*\}$'
            m = re.match(pattern, line_raw)
            if not m:
                print(line)
                raise ValueError("not a single-line if")

            cond = m.group('cond')
            body = m.group('body')

            obf_lines.append(f"uint64_t obf_local_{self.local_iter} = {cond};")
            self.local_iter += 1
            obf_lines.append(f"uint64_t obf_local_{self.local_iter};")
            self.local_iter += 1
        else:
            obf_lines.append(f"uint64_t obf_local_{self.local_iter};")
            self.local_iter += 1
            obf_lines.append(f"uint64_t obf_local_{self.local_iter};")
            self.local_iter += 1

        obf_lines.append(f"G_{const_glob} = {const_val}ULL;")
        obf_lines.append(f"G_{var_glob1} = obf_local_{self.local_iter-2};")
        obf_lines.append(f"G_{var_glob2} = obf_local_{self.local_iter-1};")

        if is_if:
            obf_lines.append(f"switch (mba_{const_glob}_{const_val}_{var_glob1}_{var_glob2}_{out}_{out2}()) "+"{")
        else:
            obf_lines.append(f"switch (mba_{const_glob}_{const_val}_{var_glob1}_{var_glob2}_{out}()) "+"{")
        
        case_l = set()
        case_l.add(out)
        case_l.add(out2)
        while len(case_l) < self.case_cnt:
            tmp = random.randint(0, (1<<64)-1)
            if tmp == out:
                continue
            case_l.add(tmp)
        case_l = sorted(case_l)
        for elem in case_l:
            if elem == out2:
                continue
            obf_lines.append(f"\tcase {elem}ULL:")
            if elem == out:
                if is_if:
                    obf_lines.append(f"\t\t{body.strip()}")
                else:
                    obf_lines.append(f"\t\t{line_raw}")
                obf_lines.append(f"\t\tbreak;")
            else:
                for i in range(random.randint(0x8, 0x10)):
                    obf_lines.append(f'\t\tasm volatile("ud2");')
                obf_lines.append(f"\t\tbreak;")
                # obf_lines.append(f"\t\tG_{random.randint(0, self.glob_cnt-1)}={random.randint(0, (1<<64)-1)}ULL;")
        # obf_lines.append(f"\tdefault:")
        # obf_lines.append(f"\t\tG_{random.randint(0, self.glob_cnt-1)}={random.randint(0, (1<<64)-1)}ULL;")
        obf_lines.append("}")
        
        obf_res = "".join([" "*indent+l+"\n" for l in obf_lines])
        return obf_res
    
    def obf(self):

        with open(self.src, "r") as f:
            lines = f.readlines()

        black_list = [
            "{", "}", "else", "."
            "for", "while", "switch", "case", ":", "default", "return", "bool",
            "void", "char", "int", "__", "long", "float", "double", "break", "size_t", "FILE",
            "//", "typedef", "struct", "Puzzle", "Inequality", "Solver", "Cage", "sha256_ctx"
        ]

        # filter if the line can be obfuscated
        for idx, line in enumerate(lines):
            is_black = False
            for black in black_list:
                if black in line:
                    is_black = True
            if "if" in line:
                is_black = False
            if is_black:
                continue
            if line.strip() == "":
                continue

            if "if" not in line and random.random() > self.obf_prob:
                continue
            elif "if" not in line:
                obf_line = self.obf_line(lines[idx])
            else:
                obf_line = self.obf_line(lines[idx], is_if=True)
            lines[idx] = obf_line

        with open(self.out, "w") as f:
            f.write(f'#include "{self.opaque_dir}/glob.h"\n')
            f.write(f'#include "{self.opaque_dir}/opaque.h"\n')
            for line in lines:
                f.write(line)
        return

if __name__ == "__main__":
    obf = Obfuscator("./main.pp.c", "./main.obf.c", "./opaque", case_cnt=20, obf_prob=0.5)
    obf.obf()
