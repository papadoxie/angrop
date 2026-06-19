"""
Architecture-dependent configurations
"""
import struct
import logging

l = logging.getLogger(__name__)

# GNU_PROPERTY_X86_FEATURE_1_AND and its IBT/SHSTK bits (see the x86-64 psABI)
GNU_PROPERTY_X86_FEATURE_1_AND = 0xc0000002
GNU_PROPERTY_X86_FEATURE_1_IBT = 0x1
GNU_PROPERTY_X86_FEATURE_1_SHSTK = 0x2
NT_GNU_PROPERTY_TYPE_0 = 5


class ROPArch:
    def __init__(self, project, kernel_mode=False):
        self.project = project
        self.kernel_mode = kernel_mode
        self.max_sym_mem_access = 1
        self.alignment = project.arch.instruction_alignment
        self.reg_list = self._get_reg_list()
        self.reg_set = set(self.reg_list) # backward compatibility, will be removed
        self.max_block_size = None
        self.fast_mode_max_block_size = None

        a = project.arch
        self.stack_pointer = a.register_names[a.sp_offset]
        self.base_pointer = a.register_names[a.bp_offset]
        self.syscall_insts = None
        self.ret_insts = None
        self.execve_num = None
        self.sigreturn_num = None

        # Intel CET state. `endbr_bytes` is the architecture's endbr opcode (only
        # set on x86/amd64); `ibt`/`shstk` reflect whether forward-edge IBT and the
        # shadow stack are in effect (detected or forced via `apply_cet`).
        self.ibt = False
        self.shstk = False
        self.endbr_bytes = None

    def addr_has_endbr(self, addr) -> bool:
        """
        Pure, total predicate: True iff the bytes at `addr` are exactly this arch's
        endbr opcode. Only meaningful at instruction-entry addresses (gadget entries
        are, by construction), so a raw-byte compare cannot false-positive on data or
        mid-instruction bytes. Never raises, never mutates.
        """
        if self.endbr_bytes is None:
            return False
        try:
            raw = self.project.loader.memory.load(addr, len(self.endbr_bytes))
        except KeyError:
            return False
        return bytes(raw) == self.endbr_bytes

    def apply_cet(self, cet):
        """
        Resolve the CET configuration. `cet is True` forces it on (only meaningful on
        x86/amd64); `cet is False` forces it off; `cet is None` auto-detects from the
        binary's GNU property note.
        """
        if cet is False:
            self.ibt = False
            self.shstk = False
        elif cet is True:
            if self.endbr_bytes is None:
                l.warning("cet=True requested but this architecture has no IBT/endbr support; ignoring")
                self.ibt = False
                self.shstk = False
            else:
                self.ibt = True
                self.shstk = True
        else:
            self.ibt, self.shstk = self._detect_cet()

        if self.shstk:
            l.warning("shadow stack present -> the engine will build ret-free JOP chains")
        elif self.ibt:
            l.info("IBT present -> indirect-branch targets must be endbr")
        return self.ibt, self.shstk

    def _detect_cet(self):
        """
        Base implementation: no CET support. x86/amd64 override this to parse the
        GNU_PROPERTY_X86_FEATURE_1_AND note.
        """
        return False, False

    def _get_reg_list(self):
        """
        get the set of names of general-purpose registers + bp
        because bp is usually considered as general-purpose these days
        """
        arch = self.project.arch
        sp_reg = arch.register_names[arch.sp_offset]
        ip_reg = arch.register_names[arch.ip_offset]
        bp_reg = arch.register_names[arch.bp_offset]

        # get list of general-purpose registers
        default_regs = arch.default_symbolic_registers
        # prune the register list of the instruction pointer and the stack pointer
        reg_list = [r for r in default_regs if r not in (sp_reg, ip_reg, bp_reg)]
        reg_list.append(bp_reg)
        return reg_list

    def block_make_sense(self, block) -> bool:
        return True

class X86(ROPArch):
    def __init__(self, project, kernel_mode=False):
        super().__init__(project, kernel_mode=kernel_mode)
        self.max_block_size = 20
        self.fast_mode_max_block_size = 12
        self.syscall_insts = {b"\xcd\x80"} # int 0x80
        self.ret_insts = {b"\xc2", b"\xc3", b"\xca", b"\xcb"}
        self.segment_regs = {"cs", "ds", "es", "fs", "gs", "ss"}
        self.execve_num = 0xb
        self.sigreturn_num = 0x77
        self.endbr_bytes = b"\xf3\x0f\x1e\xfb" # endbr32

    def _detect_cet(self):
        mask = self._x86_feature_1_and()
        if mask is None:
            return False, False
        return (bool(mask & GNU_PROPERTY_X86_FEATURE_1_IBT),
                bool(mask & GNU_PROPERTY_X86_FEATURE_1_SHSTK))

    def _x86_feature_1_and(self):
        """
        Return the GNU_PROPERTY_X86_FEATURE_1_AND bitmask from the binary's
        `.note.gnu.property` note, or None if it can't be found. Tries the mapped
        section first, then falls back to parsing the file with pyelftools. Defensive
        throughout: any failure yields None so detection degrades to "CET off".
        """
        is_64 = self.project.arch.bits == 64
        obj = self.project.loader.main_object

        # (a) the mapped .note.gnu.property section
        try:
            for sec in getattr(obj, "sections", []):
                if sec.name != ".note.gnu.property":
                    continue
                try:
                    raw = bytes(self.project.loader.memory.load(sec.vaddr, sec.memsize))
                except KeyError:
                    raw = None
                if raw:
                    mask = self._parse_gnu_property_note(raw, is_64)
                    if mask is not None:
                        return mask
        except Exception: # pylint: disable=broad-except
            pass

        # (b)/(c) parse the note straight from the on-disk file via pyelftools
        try:
            from elftools.elf.elffile import ELFFile # pylint: disable=import-outside-toplevel
            path = getattr(obj, "binary", None)
            if not path:
                return None
            with open(path, "rb") as f:
                sec = ELFFile(f).get_section_by_name(".note.gnu.property")
                if sec is None:
                    return None
                return self._parse_gnu_property_note(sec.data(), is_64)
        except Exception: # pylint: disable=broad-except
            return None

    def _parse_gnu_property_note(self, data, is_64):
        """
        Parse the raw bytes of a `.note.gnu.property` section and return the
        GNU_PROPERTY_X86_FEATURE_1_AND mask, or None. Walks the ELF notes, then the
        program properties inside the matching note.
        """
        e = "<" if self.project.arch.memory_endness == "Iend_LE" else ">"
        off = 0
        n = len(data)
        while off + 12 <= n:
            namesz, descsz, ntype = struct.unpack_from(e + "III", data, off)
            off += 12
            name = data[off:off + namesz]
            off += (namesz + 3) & ~3 # notes are 4-byte aligned
            desc = data[off:off + descsz]
            off += (descsz + 3) & ~3
            if ntype != NT_GNU_PROPERTY_TYPE_0 or name.rstrip(b"\x00") != b"GNU":
                continue
            align = 8 if is_64 else 4 # property data alignment is the ELF word size
            poff = 0
            while poff + 8 <= len(desc):
                pr_type, pr_datasz = struct.unpack_from(e + "II", desc, poff)
                poff += 8
                pr_data = desc[poff:poff + pr_datasz]
                poff += (pr_datasz + align - 1) & ~(align - 1)
                if pr_type == GNU_PROPERTY_X86_FEATURE_1_AND and len(pr_data) >= 4:
                    return struct.unpack_from(e + "I", pr_data, 0)[0]
        return None

    def _x86_block_make_sense(self, block):
        capstr = str(block.capstone).lower()

        for inst in block.capstone.insns:
            if inst.mnemonic == 'ret' and inst.op_str:
                n = int(inst.op_str, 16)
                if n % self.project.arch.bytes != 0 or n >= 0x100:
                    return False

            if inst.mnemonic == 'int' and inst.op_str:
                n = int(inst.op_str, 16)
                if n != 0x80:
                    return False

        # currently, angrop does not handle "repz ret" correctly, we filter it
        if any(x in capstr for x in ('cli', 'rex', 'repz ret', 'retf', 'hlt', 'wait', 'loop', 'lock')):
            return False
        if not self.kernel_mode:
            if "fs:" in capstr or "gs:" in capstr or "iret" in capstr:
                return False
        if block.size < 1:
            return False
        return True

    def block_make_sense(self, block):
        if not self._x86_block_make_sense(block):
            return False
        for x in block.capstone.insns:
            if x.mnemonic == 'syscall':
                return False
        return True

class AMD64(X86):
    def __init__(self, project, kernel_mode=False):
        super().__init__(project, kernel_mode=kernel_mode)
        self.syscall_insts = {b"\x0f\x05"} # syscall
        self.segment_regs = {"cs_seg", "ds_seg", "es_seg", "fs_seg", "gs_seg", "ss_seg"}
        self.execve_num = 0x3b
        self.sigreturn_num = 0xf
        self.endbr_bytes = b"\xf3\x0f\x1e\xfa" # endbr64

    def block_make_sense(self, block):
        return self._x86_block_make_sense(block)

arm_conditional_postfix = ['eq', 'ne', 'cs', 'hs', 'cc', 'lo', 'mi', 'pl',
                           'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al']
class ARM(ROPArch):

    def __init__(self, project, kernel_mode=False):
        super().__init__(project, kernel_mode=kernel_mode)
        self.is_thumb = False # by default, we don't use thumb mode
        self.alignment = self.project.arch.bytes
        self.max_block_size = self.alignment * 8
        self.fast_mode_max_block_size = self.alignment * 6
        self.execve_num = 0xb

    def set_thumb(self):
        self.is_thumb = True
        self.alignment = 2
        self.max_block_size = self.alignment * 8
        self.fast_mode_max_block_size = self.alignment * 6

    def set_arm(self):
        self.is_thumb = False
        self.alignment = self.project.arch.bytes
        self.max_block_size = self.alignment * 8
        self.fast_mode_max_block_size = self.alignment * 6

    def block_make_sense(self, block):
        # disable conditional jumps, for now
        # FIXME: we should handle conditional jumps, they are useful
        for insn in block.capstone.insns:
            if insn.insn.mnemonic[-2:] in arm_conditional_postfix:
                return False
        return True

class AARCH64(ROPArch):
    def __init__(self, project, kernel_mode=False):
        super().__init__(project, kernel_mode=kernel_mode)
        self.ret_insts = {b'\xc0\x03_\xd6'}
        self.max_block_size = self.alignment * 10
        self.fast_mode_max_block_size = self.alignment * 6
        self.execve_num = 0xdd

    def block_make_sense(self, block):
        for x in block.capstone.insns:
            # won't be able to ROP with PAC
            if x.mnemonic == 'autiasp':
                return False
        return True

class MIPS(ROPArch):
    def __init__(self, project, kernel_mode=False):
        super().__init__(project, kernel_mode=kernel_mode)
        self.alignment = self.project.arch.bytes
        self.max_block_size = self.alignment * 8
        self.fast_mode_max_block_size = self.alignment * 6
        self.execve_num = 0xfab
        self.syscall_insts = {b"\x0c\x00\x00\x00"} # syscall

class RISCV64(ROPArch):
    def __init__(self, project, kernel_mode=False):
        super().__init__(project, kernel_mode=kernel_mode)
        self.ret_insts = {b"\x82\x80"}
        self.max_block_size = self.alignment * 10
        self.fast_mode_max_block_size = self.alignment * 6
        self.execve_num = 0xdd

def get_arch(project, kernel_mode=False):
    name = project.arch.name
    mode = kernel_mode
    if name == 'X86':
        return X86(project, kernel_mode=mode)
    elif name == 'AMD64':
        return AMD64(project, kernel_mode=mode)
    elif name.startswith('ARM'):
        return ARM(project, kernel_mode=mode)
    elif name == 'AARCH64':
        return AARCH64(project, kernel_mode=mode)
    elif name == 'RISCV64':
        return RISCV64(project, kernel_mode=mode)
    elif name.startswith('MIPS'):
        return MIPS(project, kernel_mode=mode)
    else:
        raise ValueError(f"Unknown arch: {name}")
