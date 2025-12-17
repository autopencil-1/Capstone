from capstone import Cs, CsInsn, CS_ARCH_X86, CS_MODE_64
from capstone import CS_GRP_JUMP, CS_GRP_RET
import capstone.x86 as x86
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
import lief
import random
from typing import Tuple
from asm_gen import generate_random_x64_block

"""
1. .text 영역 scan
    1-1. JMP에 대해 XREF Table 생성
    1-2. basic block들의 시작 주소 수집
2. JMP XREF가 존재하는 code block들 순회
3. nop으로 시작하는 code block인 경우
    3-1. 해당 코드 블럭의 마지막 jmp문 빼고 랜덤 어셈으로 패치
    3-2. 해당 코드 블럭의 jmp xref의 disp를 이상하게 패치
"""

class Obfuscator:
    def __init__(self, bin_path: str, anti_disasm_rate: float = 0.5, random_dummy_rate: float = 0.2):
        self.basic_block = list()
        self.jmp_xref_table = list()
        self.bin: lief.ELF.Binary = lief.parse(bin_path)
        self.anti_disasm_rate = anti_disasm_rate
        self.random_dummy_rate = random_dummy_rate

        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self.text = None

        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)

    def scan_text_section(self):
        """
        basic block 수집
        jmp <imm> 정보 수집
        """

        text_sec = None
        for sec in self.bin.sections:
            if sec.name == ".text":
                text_sec = sec
                break
        if text_sec is None:
            raise RuntimeError("Failed to find .text section")
        self.text = text_sec

        code = self.bin.get_content_from_virtual_address(text_sec.virtual_address, text_sec.size)
        
        is_basic_block = True
        for insn in self.md.disasm(code, offset=text_sec.virtual_address):
            if is_basic_block:
                self.basic_block.append(insn.address)
                is_basic_block = False
            
            if insn.group(CS_GRP_JUMP):
                operand = insn.operands[0]
                if operand.type == x86.CS_OP_MEM:
                    self.jmp_xref_table.append(operand.mem.disp + insn.adress + insn.size)
                if operand.type == x86.CS_OP_IMM:
                    self.jmp_xref_table.append(operand.imm)

                if insn.id == x86.X86_INS_JMP:
                    is_basic_block = True
            elif insn.group(CS_GRP_RET):
                is_basic_block = True
        return
    
    def find_block_end(self, code, off):
        for insn in self.md.disasm(code, off):
            if insn.id == x86.X86_INS_JMP:
                return insn.address
        return None

    def obfuscate(self):
        MAX_BLOCK_SIZE = 0x100
        SIG = b"\x0F\x0B"

        obf_jmp_asm_addr_l = list()

        # collect where to obfuscate
        for block in self.jmp_xref_table:
            sig_byte = bytes(self.bin.get_content_from_virtual_address(block, 2))
            if sig_byte != SIG:
                continue

            block_code = self.bin.get_content_from_virtual_address(block, MAX_BLOCK_SIZE)
            jmp_asm_addr = self.find_block_end(block_code, block)
            if jmp_asm_addr != None:
                obf_jmp_asm_addr_l.append((block, jmp_asm_addr))
        # patch
        for block, jmp_asm_addr in obf_jmp_asm_addr_l:
            
            if random.random() < self.anti_disasm_rate:
                where_to_jmp = self.text.virtual_address + random.randint(0, self.text.size-1)
            else:
                where_to_jmp = random.choice(self.basic_block)

            old_jmp_asm = self.bin.get_content_from_virtual_address(jmp_asm_addr, 5)
            try:
                insn = next(self.md.disasm(old_jmp_asm, jmp_asm_addr))
            except:
                print(hex(jmp_asm_addr))
                exit()

            if insn.size == 2:
                near = jmp_asm_addr - 3
                short = jmp_asm_addr
            else:
                near = jmp_asm_addr
                short = jmp_asm_addr + 3
            
            if (where_to_jmp - (near + 5)) > 0x7F or (where_to_jmp - (near + 5)) < -0x80:
                N = near - block
                
                if random.random() < self.random_dummy_rate:
                    blob = bytes([random.randint(0, 255) for _ in range(N)])
                else:
                    asm, blob = generate_random_x64_block(N)
                self.bin.patch_address(block, list(blob))

                code, size = self.ks.asm(f"jmp {where_to_jmp}", addr=near)
                self.bin.patch_address(near, code)
            else:
                N = short - block

                if random.random() < self.random_dummy_rate:
                    blob = bytes([random.randint(0, 255) for _ in range(N)])
                else:
                    asm, blob = generate_random_x64_block(N)
                self.bin.patch_address(block, list(blob))
                
                code, size = self.ks.asm(f"jmp {where_to_jmp}", addr=short)
                self.bin.patch_address(short, code)
        
        builder = lief.ELF.Builder(self.bin)
        builder.build()
        builder.write("main_obf")

        print("PATCHED SUCCESS") 

        return

if __name__ == "__main__":
    obf = Obfuscator("./main")

    obf.scan_text_section()
    obf.obfuscate()